"""mitmproxy addon porting crhywun/g1-acq (v7.6.0) logic for Windows + iPhone."""

import html
import json
import os
import re
from datetime import datetime, timezone
from mitmproxy import http

VERSION = "g1-acq-v7.6"
REPORT_VERSION = "v7.6.0-mitm"
SOURCE_PREFIX = "g1.ios.2tb."
TARGET = "g1.2tb.ai.12months_ip_90p"

SKU_MAP = {
    "g1.ios.20tb.m.v2": "g1.20tb.1month_eft.acq",
    "g1.ios.30tb.ai.pro.m": "g1.ai.ultra.1month_eft.acq",
}
FALLBACK = {
    "g1.20tb.1month_eft.acq": "g1.20tb.3months_ip_90p.acq",
    "g1.ai.ultra.1month_eft.acq": "g1.ai.ultra.3months_ip_90p.acq",
}

SCAN_LIMIT = 300
RECENT_LIMIT = 10
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "g1_acq_state.json")

REPORT_URL_RE = re.compile(r"^https://one\.google\.com/g1-sku-report/?(?:\?.*)?$")
AI_URL_RE = re.compile(r"^https://one\.google\.com/ai\?")
VALID_ID_RE = re.compile(r"^(?:g1\.|com\.google\.one\.)[A-Za-z0-9._-]{1,160}$")
DISCOVERY_TOKEN_RE = re.compile(
    r"(^|[^A-Za-z0-9._@%-])((?:g1\.|com\.google\.one\.)[A-Za-z0-9._-]+)(?=$|[^A-Za-z0-9._-])"
)
REWRITE_TOKEN_RE = re.compile(
    r"(^|[^A-Za-z0-9._@%-])(g1\.[A-Za-z0-9._-]+)(?=$|[^A-Za-z0-9._-])"
)
ESCAPED_DOT_RE = re.compile(r"\\u002e|\\x2e|&#0*46;|&#x0*2e;|&period;", re.IGNORECASE)
OBSERVED_ACQ_RE = re.compile(r"g1\.[a-z0-9._]{2,60}acq")

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


def utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def load_state() -> dict:
    """Load persisted scan and test state from local JSON file."""
    if not os.path.exists(STATE_FILE):
        return {"scan": {}, "test": {}}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return {"scan": data.get("scan", {}), "test": data.get("test", {})}
    except Exception:
        pass
    return {"scan": {}, "test": {}}


def save_state(state: dict) -> bool:
    """Persist scan and test state atomically to local JSON file."""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def safe_route(url: str) -> str:
    """Normalize one.google.com path without keeping query parameters."""
    path = re.split(r"[?#]", url.replace("https://one.google.com", "", 1))[0].rstrip("/") or "/"
    if path in ("/", "/ai", "/plans"):
        return path
    if re.match(r"^/_/[^?#]+/data/batchexecute$", path):
        return "/_/…/data/batchexecute"
    return "[other one.google.com path]"


def extract_text_body(resp: http.Response):
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


def collect_original_skus(url: str, original_body) -> None:
    """Passively collect unique g1.* and com.google.one.* SKUs before any rewrite."""
    now = utc_now()
    state = load_state()
    saved = state.get("scan") or {}
    if saved.get("schemaVersion") != 1:
        saved = {}

    by_id = {}
    for row in (saved.get("skus") or [])[:SCAN_LIMIT]:
        if isinstance(row, dict) and isinstance(row.get("id"), str) and VALID_ID_RE.match(row["id"]):
            rid = row["id"]
            if rid not in by_id:
                by_id[rid] = {
                    "id": rid,
                    "count": max(0, int(row.get("count") or 0)),
                    "lastSeen": str(row.get("lastSeen") or "")[:32],
                }

    is_text = isinstance(original_body, str)
    found = {}
    hit_count = 0
    added_count = 0
    omitted_count = 0
    truncated = bool(saved.get("truncated") is True)

    if is_text:
        decoded = ESCAPED_DOT_RE.sub(".", original_body)
        for m in DISCOVERY_TOKEN_RE.finditer(decoded):
            sku_id = m.group(2)
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
    if not is_text:
        status = "non-text"
    elif added_count > 0:
        status = "new-skus"
    elif omitted_count > 0:
        status = "limit-reached"
    elif candidate_count > 0:
        status = "known-skus"
    else:
        status = "no-skus"

    recent = list(saved.get("recentResponses") or [])[-RECENT_LIMIT:]
    recent.append(
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

    state["scan"] = {
        "schemaVersion": 1,
        "version": VERSION,
        "updatedAt": now,
        "scannedResponses": int(saved.get("scannedResponses") or 0) + (1 if is_text else 0),
        "matchedResponses": int(saved.get("matchedResponses") or 0) + (1 if hit_count > 0 else 0),
        "nonTextResponses": int(saved.get("nonTextResponses") or 0) + (0 if is_text else 1),
        "recentResponses": recent[-RECENT_LIMIT:],
        "limit": SCAN_LIMIT,
        "truncated": truncated,
        "skus": [by_id[k] for k in sorted(by_id.keys())],
    }
    stored = save_state(state)
    print(
        f"[g1-acq] {VERSION} status={status} addedCount={added_count} "
        f"candidates={candidate_count} omittedCount={omitted_count} "
        f"occurrences={hit_count} saved={'yes' if stored else 'no'}"
    )
    for sku_id in sorted(found.keys())[:SCAN_LIMIT]:
        print(f"[g1-acq]   {sku_id} x{found[sku_id]}")


def build_report_payload(state: dict) -> dict:
    """Build JSON report payload matching g1-sku-report structure."""
    scan = state.get("scan") or {}
    test = state.get("test") or {}
    return {
        "reportVersion": REPORT_VERSION,
        "configuredTarget": TARGET,
        "scan": scan,
        "test": test,
    }


def render_html(payload: dict, cleared_msg: str = "") -> str:
    """Render local diagnostic HTML page for Safari on iPhone."""
    scan = payload.get("scan") or {}
    test = payload.get("test") or {}
    skus = scan.get("skus") or []
    recent = list(reversed(scan.get("recentResponses") or []))
    matched = test.get("matchedFrom") or []

    sku_rows = "".join(
        f"<tr><td><code>{html.escape(r['id'])}</code></td><td>{r['count']}</td><td>{html.escape(r.get('lastSeen', ''))}</td></tr>"
        for r in skus
    ) or "<tr><td colspan=3>Chưa có dữ liệu SKU.</td></tr>"

    recent_rows = "".join(
        f"<tr><td>{html.escape(e['at'])}</td><td>{html.escape(e['path'])}</td><td>{html.escape(e['status'])}</td>"
        f"<td>{e['candidateCount']}</td><td>{e['addedCount']}</td><td>{e['omittedCount']}</td></tr>"
        for e in recent
    ) or "<tr><td colspan=6>Chưa có phản hồi nào.</td></tr>"

    match_rows = "".join(
        f"<tr><td><code>{html.escape(m['id'])}</code></td><td><code>{html.escape(m['to'])}</code></td>"
        f"<td>{m['count']}</td><td>{'Có' if m.get('fallback') else 'Không'}</td></tr>"
        for m in matched
    ) or "<tr><td colspan=4>Chưa có bản ghi viết lại.</td></tr>"

    return f"""<!doctype html>
<html lang="vi">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google One SKU Local Report (mitmproxy)</title>
<style>
body{{font:15px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;max-width:960px;margin:20px auto;padding:0 16px;background:#f5f7fa;color:#1c2737}}
section{{background:#fff;border:1px solid #dde3ec;border-radius:12px;padding:16px;margin:16px 0}}
.badge{{display:inline-block;background:#e0f4e8;color:#176238;padding:4px 10px;border-radius:8px;font-weight:600}}
.actions{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}
.btn{{padding:9px 14px;border-radius:8px;text-decoration:none;background:#1259be;color:#fff;font-weight:500}}
.btn.sec{{background:#e4eaf3;color:#1c2737}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{padding:8px;border-bottom:1px solid #e5e7eb;text-align:left}}
.scroll{{overflow-x:auto}}
code{{word-break:break-all}}
</style>
<h1>Google One SKU Local Report</h1>
<p class="badge">mitmproxy cục bộ đang hoạt động · {html.escape(REPORT_VERSION)}</p>
{f'<p><strong>{html.escape(cleared_msg)}</strong></p>' if cleared_msg else ''}
<div class="actions">
  <a class="btn" href="https://one.google.com/g1-sku-report?format=json">Tải JSON</a>
  <a class="btn sec" href="https://one.google.com/g1-sku-report">Làm mới</a>
  <a class="btn sec" href="https://one.google.com/g1-sku-report?clear=1">Xóa dữ liệu</a>
</div>
<section>
  <h2>Thống kê thu thập</h2>
  <p>Text responses: {scan.get('scannedResponses', 0)} | Có SKU: {scan.get('matchedResponses', 0)} | Non-text: {scan.get('nonTextResponses', 0)} | Tổng ID: {len(skus)}</p>
  <p>Cập nhật (UTC): <code>{html.escape(str(scan.get('updatedAt', 'Chưa có')))}</code></p>
  <div class="scroll"><table><thead><tr><th>Thời gian</th><th>Path</th><th>Trạng thái</th><th>SKU</th><th>Mới</th><th>Bỏ qua</th></tr></thead><tbody>{recent_rows}</tbody></table></div>
</section>
<section>
  <h2>Kết quả ánh xạ gần nhất (/ai?)</h2>
  <p>Trạng thái: <strong>{html.escape(str(test.get('status', 'Chưa có')))}</strong> | Tổng hit: {test.get('hitCount', 0)} | 2TB hit: {test.get('annualHitCount', 0)}</p>
  <div class="scroll"><table><thead><tr><th>SKU gốc</th><th>SKU đích</th><th>Số lần</th><th>Fallback</th></tr></thead><tbody>{match_rows}</tbody></table></div>
</section>
<section>
  <h2>Danh sách SKU gốc đã thu thập</h2>
  <div class="scroll"><table><thead><tr><th>SKU ID</th><th>Số lần</th><th>Thấy lần cuối (UTC)</th></tr></thead><tbody>{sku_rows}</tbody></table></div>
</section>
</html>"""


def request(flow: http.HTTPFlow) -> None:
    """Serve local diagnostic report at https://one.google.com/g1-sku-report."""
    url = flow.request.pretty_url
    if not REPORT_URL_RE.match(url):
        return

    cleared_msg = ""
    if re.search(r"(?:\?|&)clear=1(?:&|$)", url):
        save_state({"scan": {}, "test": {}})
        cleared_msg = "Đã xóa toàn bộ dữ liệu thu thập và lịch sử ánh xạ."

    state = load_state()
    payload = build_report_payload(state)
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

    if re.search(r"(?:\?|&)format=json(?:&|$)", url):
        headers["Content-Type"] = "application/json; charset=utf-8"
        headers["Content-Disposition"] = 'attachment; filename="g1-sku-report.json"'
        flow.response = http.Response.make(
            200, json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), headers
        )
        return

    headers["Content-Type"] = "text/html; charset=utf-8"
    flow.response = http.Response.make(200, render_html(payload, cleared_msg).encode("utf-8"), headers)


def response(flow: http.HTTPFlow) -> None:
    """Collect SKUs on one.google.com/ and rewrite 3-tier SKUs on /ai? responses."""
    url = flow.request.pretty_url
    if not url.startswith("https://one.google.com/") or REPORT_URL_RE.match(url):
        return

    body = extract_text_body(flow.response)
    try:
        collect_original_skus(url, body)
    except Exception as exc:
        print(f"[g1-acq] SKU collection unavailable: {exc}")

    if not AI_URL_RE.match(url):
        return

    mappings = {}
    hits = 0
    annual_hits = 0
    out = body

    if isinstance(body, str):
        observed = set(OBSERVED_ACQ_RE.findall(body))

        def repl(match: re.Match) -> str:
            nonlocal hits, annual_hits
            before = match.group(1)
            sku_id = match.group(2)
            is_annual = sku_id.startswith(SOURCE_PREFIX) and len(sku_id) > len(SOURCE_PREFIX)
            fallback = False

            if is_annual:
                to = TARGET
            elif sku_id in SKU_MAP:
                to = SKU_MAP[sku_id]
                if to not in observed and to in FALLBACK and FALLBACK[to] in observed:
                    to = FALLBACK[to]
                    fallback = True
            else:
                return match.group(0)

            if sku_id not in mappings:
                mappings[sku_id] = {"id": sku_id, "to": to, "count": 0, "fallback": fallback}
            mappings[sku_id]["count"] += 1
            hits += 1
            if is_annual:
                annual_hits += 1
            return before + to

        out = REWRITE_TOKEN_RE.sub(repl, body)

    sources = [mappings[k] for k in sorted(mappings.keys())]
    state = load_state()
    state["test"] = {
        "schemaVersion": 1,
        "version": VERSION,
        "updatedAt": utc_now(),
        "sourcePrefix": SOURCE_PREFIX,
        "target": TARGET,
        "targetOrigin": "user-specified",
        "hitCount": hits,
        "annualHitCount": annual_hits,
        "matchedFrom": sources,
        "status": "non-text" if not isinstance(body, str) else ("rewritten" if hits else "no-match"),
    }
    save_state(state)

    print(f"[g1-acq] {VERSION} hits={hits} annualHits={annual_hits}")
    for s in sources:
        fb = f" fallback={s['to']}" if s["fallback"] else ""
        print(f"[g1-acq]   {s['id']} -> {s['to']} x{s['count']}{fb}")

    if hits > 0 and isinstance(out, str):
        flow.response.text = out
