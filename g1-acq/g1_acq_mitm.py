"""mitmproxy addon porting crhywun/g1-acq (v7.12.0) logic for Windows + iPhone."""

from __future__ import annotations

import json
import math
import os
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Any

from mitmproxy import http

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import g1_sku_report  # noqa: E402
import mapping_config  # noqa: E402

VERSION = "g1-acq-v7.12-mappings"
REPORT_VERSION = g1_sku_report.VERSION
SOURCE_PREFIX = mapping_config.SOURCE_PREFIX
TEST_KEY = g1_sku_report.TEST_KEY
SCAN_KEY = g1_sku_report.SCAN_KEY

SCAN_LIMIT = 300
RECENT_LIMIT = 10
MAX_EVENT_COUNT = 9007199254740991
STATE_FILE = os.path.join(SCRIPT_DIR, "g1_acq_state.json")

KEY_TO_SLOT = {
    SCAN_KEY: "scan",
    TEST_KEY: "test",
    mapping_config.KEY: "mappings",
}

ONE_GOOGLE_RE = re.compile(r"\Ahttps://one\.google\.com/")
REPORT_URL_RE = g1_sku_report.REPORT_URL_RE
AI_URL_RE = re.compile(r"\Ahttps://one\.google\.com/ai\?")
VALID_ID_RE = re.compile(r"\A(?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._-]{1,160}\Z")
TOKEN_RE = re.compile(
    r"(\A|[^A-Za-z0-9._@%-])((?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._-]+)(?=\Z|[^A-Za-z0-9._-])"
)
ESCAPED_DOT_RE = re.compile(r"\\u002e|\\x2e|&#0*46;|&#x0*2e;|&period;", re.IGNORECASE)
EVENT_AT_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")

BINARY_PREFIXES = (
    "image/",
    "video/",
    "audio/",
    "font/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/wasm",
)


class LocalStateStore:
    """Thread-safe JSON file store implementing $persistentStore read/write semantics."""

    def __init__(self, state_file: str = STATE_FILE) -> None:
        self.state_file = state_file
        self._lock = threading.Lock()

    def _read_root(self) -> tuple[dict[str, Any] | None, str | None]:
        if not os.path.exists(self.state_file):
            return {"scan": {}, "test": {}}, None
        with open(self.state_file, "r", encoding="utf-8") as f:
            raw = f.read()
        if not raw.strip():
            return {"scan": {}, "test": {}}, None
        try:
            data = json.loads(raw)
        except Exception:
            return None, raw
        if not isinstance(data, dict):
            return None, raw
        return data, raw

    def read(self, key: str) -> str | None:
        slot = KEY_TO_SLOT.get(key)
        if slot is None:
            return None
        with self._lock:
            data, raw_file = self._read_root()
            if data is None:
                return raw_file if key == mapping_config.KEY else "{}"
            if slot not in data or data[slot] is None:
                return None
            val = data[slot]
            if isinstance(val, str):
                return val
            return json.dumps(val, ensure_ascii=False)

    def write(self, value: str, key: str) -> bool:
        slot = KEY_TO_SLOT.get(key)
        if slot is None or not isinstance(value, str):
            return False
        try:
            parsed = json.loads(value)
        except Exception:
            parsed = value

        with self._lock:
            try:
                data, _ = self._read_root()
                if data is None:
                    data = {"scan": {}, "test": {}}
                else:
                    data = dict(data)
                data[slot] = parsed
                tmp_path = f"{self.state_file}.tmp.{os.getpid()}.{threading.get_ident()}"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                os.replace(tmp_path, self.state_file)
                return True
            except Exception:
                return False


DEFAULT_STORE = LocalStateStore()


def utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_route(url: str) -> str:
    """Normalize one.google.com path without keeping query parameters."""
    path = re.split(r"[?#]", url.replace("https://one.google.com", "", 1))[0].rstrip("/") or "/"
    if path in ("/", "/ai", "/plans"):
        return path
    if re.match(r"\A/_/[^?#]+/data/batchexecute\Z", path):
        return "/_/…/data/batchexecute"
    return g1_sku_report.OTHER_PATH_LABEL


def response_status(body_type: str, candidate_count: int, added_count: int, omitted_count: int) -> str:
    """Compute scan event status matching crhywun/g1-acq v7.12.0."""
    if body_type == "non-text":
        return "non-text"
    if added_count > 0:
        return "new-skus"
    if omitted_count > 0:
        return "limit-reached"
    return "known-skus" if candidate_count > 0 else "no-skus"


def _prior_count(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        num = float(value)
    except Exception:
        return 0
    return int(math.floor(num)) if math.isfinite(num) and num > 0 else 0


def _prior_response(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    at = row.get("at")
    if not isinstance(at, str) or not EVENT_AT_RE.match(at):
        return None
    try:
        parsed = datetime.strptime(at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != at:
            return None
    except Exception:
        return None

    path = row.get("path")
    if path == "[其他 one.google.com 路径]":
        path = g1_sku_report.OTHER_PATH_LABEL
    if path not in g1_sku_report.SCAN_PATHS:
        return None

    body_type = row.get("bodyType")
    if body_type not in ("text", "non-text"):
        return None

    def counter(val: Any, maximum: int) -> int | None:
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            return None
        num = float(val)
        if not math.isfinite(num):
            return None
        return max(0, min(maximum, int(math.floor(num))))

    candidate_count = counter(row.get("candidateCount"), MAX_EVENT_COUNT)
    if candidate_count is None:
        return None
    added_count = counter(row.get("addedCount"), min(SCAN_LIMIT, candidate_count))
    if added_count is None:
        return None
    omitted_count = counter(row.get("omittedCount"), candidate_count - added_count)
    if omitted_count is None:
        return None
    if body_type == "non-text" and (candidate_count or added_count or omitted_count):
        return None
    if row.get("status") != response_status(body_type, candidate_count, added_count, omitted_count):
        return None

    return {
        "at": at,
        "path": path,
        "bodyType": body_type,
        "status": row["status"],
        "candidateCount": candidate_count,
        "addedCount": added_count,
        "omittedCount": omitted_count,
    }


def extract_text_body(resp: http.Response | None) -> str | None:
    """Return decoded text body for text responses, or None for binary/non-text responses."""
    if resp is None or resp.raw_content is None:
        return None
    ct = (resp.headers.get("content-type") or "").lower().split(";")[0].strip()
    if any(ct.startswith(p) for p in BINARY_PREFIXES):
        return None
    try:
        return resp.get_text(strict=True)
    except Exception:
        return None


def collect_original_skus(
    store: Any, url: str, original_body: str | None, mode: str
) -> None:
    """Passively collect unique g1.*, com.google.one.*, and com.google.gemini.* SKUs before rewriting."""
    now = utc_now()
    saved: dict[str, Any] = {}
    try:
        if store and callable(getattr(store, "read", None)):
            raw = store.read(SCAN_KEY)
            loaded = json.loads(raw or "{}")
            if isinstance(loaded, dict):
                saved = loaded
    except Exception:
        saved = {}

    if isinstance(saved.get("schemaVersion"), bool) or saved.get("schemaVersion") != 1:
        saved = {}

    by_id: dict[str, dict[str, Any]] = {}
    old_rows = saved.get("skus") if isinstance(saved.get("skus"), list) else []
    for row in old_rows[:SCAN_LIMIT]:
        if not isinstance(row, dict):
            continue
        rid = row.get("id")
        if not isinstance(rid, str) or not VALID_ID_RE.match(rid) or rid in by_id:
            continue
        last_seen = row.get("lastSeen")
        by_id[rid] = {
            "id": rid,
            "count": _prior_count(row.get("count")),
            "lastSeen": last_seen[:32] if isinstance(last_seen, str) else "",
        }

    is_text = isinstance(original_body, str)
    found: dict[str, int] = {}
    hit_count = 0
    added_count = 0
    omitted_count = 0
    truncated = saved.get("truncated") is True

    if is_text:
        decoded = ESCAPED_DOT_RE.sub(".", original_body)
        for match in TOKEN_RE.finditer(decoded):
            sku_id = match.group(2)
            if not VALID_ID_RE.match(sku_id):
                continue
            found[sku_id] = found.get(sku_id, 0) + 1
            hit_count += 1
            if sku_id not in by_id:
                if len(by_id) >= SCAN_LIMIT:
                    truncated = True
                    if found[sku_id] == 1:
                        omitted_count += 1
                    continue
                by_id[sku_id] = {"id": sku_id, "count": 0, "lastSeen": now}
                added_count += 1
            by_id[sku_id]["count"] += 1
            by_id[sku_id]["lastSeen"] = now

    candidate_count = len(found)
    body_type = "text" if is_text else "non-text"
    status = response_status(body_type, candidate_count, added_count, omitted_count)

    recent_responses: list[dict[str, Any]] = []
    old_responses = saved.get("recentResponses") if isinstance(saved.get("recentResponses"), list) else []
    for row in old_responses[-RECENT_LIMIT:]:
        ev = _prior_response(row)
        if ev is not None:
            recent_responses.append(ev)

    recent_responses.append(
        {
            "at": now,
            "path": safe_route(url),
            "bodyType": body_type,
            "status": status,
            "candidateCount": candidate_count,
            "addedCount": added_count,
            "omittedCount": omitted_count,
        }
    )

    state = {
        "schemaVersion": 1,
        "version": VERSION,
        "mode": mode,
        "updatedAt": now,
        "scannedResponses": _prior_count(saved.get("scannedResponses")) + (1 if is_text else 0),
        "matchedResponses": _prior_count(saved.get("matchedResponses")) + (1 if hit_count > 0 else 0),
        "nonTextResponses": _prior_count(saved.get("nonTextResponses")) + (0 if is_text else 1),
        "recentResponses": recent_responses[-RECENT_LIMIT:],
        "limit": SCAN_LIMIT,
        "truncated": truncated,
        "skus": [by_id[k] for k in sorted(by_id.keys())],
    }

    stored = False
    try:
        if store and callable(getattr(store, "write", None)):
            stored = bool(store.write(json.dumps(state, ensure_ascii=False), SCAN_KEY))
    except Exception:
        stored = False

    print(
        f"[g1-acq] {VERSION} status={status} addedCount={added_count} "
        f"candidates={candidate_count} omittedCount={omitted_count} "
        f"occurrences={hit_count} saved={'yes' if stored else 'no'} mode={mode}"
    )
    for sku_id in sorted(found.keys())[:SCAN_LIMIT]:
        print(f"[g1-acq]   {sku_id} x{found[sku_id]}")


def process_request(flow: http.HTTPFlow, store: Any = DEFAULT_STORE) -> None:
    """Serve local SKU manager / JSON report at https://one.google.com/g1-sku-report."""
    url = flow.request.pretty_url
    if not REPORT_URL_RE.match(url):
        return

    req_body: str | None = None
    if (flow.request.method or "GET").upper() == "POST":
        try:
            req_body = flow.request.get_text(strict=True)
        except Exception:
            req_body = None

    result = g1_sku_report.handle_report_request(
        url=url,
        method=flow.request.method or "GET",
        request_headers=flow.request.headers,
        request_body=req_body,
        storage=store,
    )
    if result is None:
        return
    flow.response = http.Response.make(
        result["status"],
        result["body"].encode("utf-8"),
        result["headers"],
    )


def process_response(flow: http.HTTPFlow, store: Any = DEFAULT_STORE) -> None:
    """Collect SKUs on one.google.com/ and rewrite configured SKU rules on /ai? responses."""
    url = flow.request.pretty_url
    if not isinstance(url, str) or not ONE_GOOGLE_RE.match(url) or REPORT_URL_RE.match(url):
        return

    engine = mapping_config.MappingConfigEngine(store)
    cfg = engine.read()
    mode = cfg["mode"]
    config_error = cfg["status"] in ("invalid", "unavailable")
    print(
        f"[g1-acq] {VERSION} mappingStatus={cfg['status']} "
        f"mappingRevision={cfg['revision']} mode={mode}"
    )

    body = extract_text_body(flow.response)
    try:
        collect_original_skus(store, url, body, mode)
    except Exception as exc:
        print(f"[g1-acq] SKU collection unavailable: {exc}")

    if not AI_URL_RE.match(url):
        return

    mappings: dict[str, dict[str, Any]] = {}
    hits = 0
    annual_hits = 0
    out = body

    if isinstance(body, str) and not config_error:
        def repl(match: re.Match[str]) -> str:
            nonlocal hits, annual_hits
            before = match.group(1)
            sku_id = match.group(2)
            rule = engine.resolve(sku_id, cfg)
            if rule is None:
                return match.group(0)
            is_annual = sku_id.startswith(SOURCE_PREFIX) and len(sku_id) > len(SOURCE_PREFIX)
            if sku_id not in mappings:
                mappings[sku_id] = {"id": sku_id, "to": rule["to"], "count": 0, "fallback": False}
            mappings[sku_id]["count"] += 1
            hits += 1
            if is_annual:
                annual_hits += 1
            return before + rule["to"]

        out = TOKEN_RE.sub(repl, body)

    sources = [mappings[k] for k in sorted(mappings.keys())]
    record_status = (
        "config-error"
        if config_error
        else ("non-text" if not isinstance(body, str) else ("rewritten" if hits else "no-match"))
    )
    record = {
        "schemaVersion": 1,
        "version": VERSION,
        "mode": mode,
        "updatedAt": utc_now(),
        "mappingRevision": cfg["revision"],
        "mappingUpdatedAt": cfg["updatedAt"],
        "mappingStatus": cfg["status"],
        "sourcePrefix": SOURCE_PREFIX,
        "target": cfg["target"],
        "targetOrigin": cfg["targetOrigin"],
        "hitCount": hits,
        "annualHitCount": annual_hits,
        "matchedFrom": sources,
        "status": record_status,
    }

    try:
        if store and callable(getattr(store, "write", None)):
            if not store.write(json.dumps(record, ensure_ascii=False), TEST_KEY):
                print("[g1-acq] local record write failed")
    except Exception:
        print("[g1-acq] local record unavailable")

    print(f"[g1-acq] {VERSION} hits={hits} annualHits={annual_hits} mode={mode}")
    for s in sources:
        print(f"[g1-acq]   {s['id']} -> {s['to']} x{s['count']}")

    if hits > 0 and isinstance(out, str) and flow.response is not None:
        flow.response.text = out


def request(flow: http.HTTPFlow) -> None:
    """mitmproxy request hook."""
    process_request(flow, DEFAULT_STORE)


def response(flow: http.HTTPFlow) -> None:
    """mitmproxy response hook."""
    process_response(flow, DEFAULT_STORE)
