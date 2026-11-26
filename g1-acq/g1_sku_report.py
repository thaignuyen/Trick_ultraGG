"""Local diagnostic report, JSON export, and POST mapping editor for mitmproxy (crhywun/g1-acq v7.12.0)."""

from __future__ import annotations

import html
import json
import math
import re
from typing import Any
from urllib.parse import quote, unquote_plus

import mapping_config

ROOT = "https://one.google.com/g1-sku-report"
VERSION = "v7.12.0-mitm"
COLLECTOR_VERSION = "g1-acq-v7.12-mappings"
DEFAULT_TARGET = "g1.2tb.ai.12months_ip_90p"
LEGACY_TARGET = "g1.2tb.ai.annual"
SCAN_KEY = "g1.sku.scan.v1"
TEST_KEY = "g1.pro.annual.test.v1"

MODE_NAMES = {
    "discount75": "Ultra 3 tháng 75p (giảm 75%, trả 25%)",
    "custom": "Ánh xạ tùy chỉnh",
    "trial": "Ultra dùng thử 1 tháng ưu tiên (lịch sử)",
    "discount": "Ultra 3 tháng 90p ưu tiên (lịch sử)",
}

SCAN_STATUSES = {
    "new-skus": "Phát hiện và lưu SKU mới",
    "known-skus": "Đã nhận phản hồi, SKU trùng với bản ghi hiện có",
    "no-skus": "Phản hồi văn bản, không chứa SKU",
    "limit-reached": "Có SKU mới nhưng đã đạt giới hạn 300 SKU",
    "non-text": "Phản hồi không phải văn bản để quét",
}

OTHER_PATH_LABEL = "[other one.google.com path]"
SCAN_PATHS = ("/", "/ai", "/plans", "/_/…/data/batchexecute", OTHER_PATH_LABEL)

REPORT_URL_RE = re.compile(r"\Ahttps://one\.google\.com/g1-sku-report/?(?:\?|\Z)")
FORMAT_JSON_RE = re.compile(r"(?:\?|&)format=json(?:&|\Z)")
CLEAR_RE = re.compile(r"(?:\?|&)clear=1(?:&|\Z)")
CONTENT_TYPE_RE = re.compile(
    r'\Aapplication/x-www-form-urlencoded(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*\Z',
    re.IGNORECASE,
)
BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
VALID_ROW_SKU_RE = re.compile(
    r"\A(?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._-]{1,160}\Z"
)
EVENT_TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z\Z")
LEGACY_VERSION_RE = re.compile(r"\A(?:pro-annual-test-v[12]|g1-acq-v7(?:\.0|\.1)?)\Z")
ORIGIN_RE = re.compile(r"\A(?:user-specified|user-configured|pattern-derived|legacy)\Z")
FALLBACK_DISCOUNT_RE = re.compile(r"_ip_(\d+p)\.acq\Z")

ALLOWED_FORM_FIELDS = ("action", "revision", "id", "match", "from", "to", "enabled", "preset")


def _base_headers() -> dict[str, str]:
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-G1-Report-Version": VERSION,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action " + ROOT
        ),
    }


def _query_param(url: str, name: str) -> str | None:
    if "?" not in url:
        return None
    query_part = url.split("?", 1)[1].split("#", 1)[0]
    for piece in query_part.split("&"):
        if "=" in piece:
            k_raw, v_raw = piece.split("=", 1)
        else:
            k_raw, v_raw = piece, ""
        if BAD_PERCENT_RE.search(k_raw) or BAD_PERCENT_RE.search(v_raw):
            return None
        try:
            key = unquote_plus(k_raw, encoding="utf-8", errors="strict")
            val = unquote_plus(v_raw, encoding="utf-8", errors="strict")
        except Exception:
            return None
        if key == name:
            return val
    return None


def _get_header_single(headers: Any, name: str) -> str | None:
    """Return single header value case-insensitively, None if absent, or '' sentinel via tuple."""
    if headers is None:
        return None
    if hasattr(headers, "get_all"):
        values = [v for v in headers.get_all(name)]
        if not values:
            return None
        if len(values) == 1 and isinstance(values[0], str):
            return values[0]
        return "__INVALID_MULTI__"
    if isinstance(headers, dict):
        matches = [v for k, v in headers.items() if isinstance(k, str) and k.lower() == name.lower()]
        if not matches:
            return None
        if len(matches) == 1 and isinstance(matches[0], str):
            return matches[0]
        return "__INVALID_MULTI__"
    return None


def _parse_form(value: str) -> dict[str, Any]:
    out: dict[str, str] = {}
    for piece in value.split("&"):
        if "=" in piece:
            k_raw, v_raw = piece.split("=", 1)
        else:
            k_raw, v_raw = piece, ""
        if BAD_PERCENT_RE.search(k_raw) or BAD_PERCENT_RE.search(v_raw):
            return {"ok": False, "error": "Mã hóa biểu mẫu không hợp lệ, vui lòng nhập lại rồi gửi."}
        try:
            key = unquote_plus(k_raw, encoding="utf-8", errors="strict")
            val = unquote_plus(v_raw, encoding="utf-8", errors="strict")
        except Exception:
            return {"ok": False, "error": "Mã hóa biểu mẫu không hợp lệ, vui lòng nhập lại rồi gửi."}
        if key not in ALLOWED_FORM_FIELDS or key in out:
            return {"ok": False, "error": "Trường biểu mẫu bị trùng hoặc không hợp lệ, vui lòng tải lại trang."}
        out[key] = val
    return {"ok": True, "fields": out}


def _problem(status: int, headers: dict[str, str], message: str) -> dict[str, Any]:
    err_headers = dict(headers)
    err_headers["Content-Type"] = "application/json; charset=utf-8"
    return {
        "status": status,
        "headers": err_headers,
        "body": json.dumps({"error": message}, ensure_ascii=False),
    }


def _load_key(storage: Any, storage_available: bool, key: str) -> dict[str, Any]:
    if not storage_available:
        return {}
    try:
        raw = storage.read(key)
        value = json.loads(raw or "{}")
        if isinstance(value, dict) and not isinstance(value.get("schemaVersion"), bool) and value.get("schemaVersion") == 1:
            return value
    except Exception:
        pass
    return {}


def _text(value: Any, length: int = 180) -> str:
    return value[:length] if isinstance(value, str) else ""


def _mode(value: Any) -> str:
    return value if value in ("discount75", "custom", "trial", "discount") else ""


def _mode_name(value: str) -> str:
    return MODE_NAMES[value] if value in MODE_NAMES else "Chưa ghi nhận"


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        try:
            if isinstance(value, bool) or value is None:
                return 0
            num = float(value)
        except Exception:
            return 0
    else:
        num = float(value)
    return int(math.floor(num)) if math.isfinite(num) and num > 0 else 0


def _sku(value: Any) -> str:
    return value if isinstance(value, str) and VALID_ROW_SKU_RE.match(value) else ""


def _rows(value: Any, with_time: bool, default_target: str = "") -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out_rows: list[dict[str, Any]] = []
    for row in value[:300]:
        if not isinstance(row, dict):
            continue
        rid = row.get("id")
        if not isinstance(rid, str) or not VALID_ROW_SKU_RE.match(rid):
            continue
        item: dict[str, Any] = {"id": rid, "count": _count(row.get("count"))}
        if with_time:
            item["lastSeen"] = _text(row.get("lastSeen"), 32)
        else:
            item["to"] = _sku(row.get("to")) or (
                default_target if rid.startswith("g1.ios.2tb.") else ""
            )
            item["fallback"] = row.get("fallback") is True
        out_rows.append(item)
    out_rows.sort(key=lambda r: r["id"])
    return out_rows


def _recent(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out_events: list[dict[str, Any]] = []
    for event in value[-10:]:
        if not isinstance(event, dict):
            continue
        at = event.get("at")
        body_type = event.get("bodyType")
        status = event.get("status")
        if (
            not isinstance(at, str)
            or not EVENT_TIME_RE.match(at)
            or body_type not in ("text", "non-text")
            or status not in SCAN_STATUSES
        ):
            continue
        raw_path = event.get("path")
        path = raw_path if raw_path in SCAN_PATHS else OTHER_PATH_LABEL
        out_events.append(
            {
                "at": at,
                "path": path,
                "bodyType": body_type,
                "status": status,
                "candidateCount": _count(event.get("candidateCount")),
                "addedCount": _count(event.get("addedCount")),
                "omittedCount": _count(event.get("omittedCount")),
            }
        )
    return out_events


def _fallback_name(row: dict[str, Any]) -> str:
    if not row.get("fallback"):
        return "Không"
    m = FALLBACK_DISCOUNT_RE.search(row.get("to") or "")
    return m.group(1) if m else "Có"


def handle_report_request(
    url: str,
    method: str,
    request_headers: Any,
    request_body: str | None,
    storage: Any,
) -> dict[str, Any] | None:
    """Handle GET/POST for https://one.google.com/g1-sku-report and return response dict."""
    if not isinstance(url, str) or not REPORT_URL_RE.match(url):
        return None

    headers = _base_headers()
    method_upper = (method or "GET").upper()
    if method_upper not in ("GET", "POST") or (method_upper == "GET" and _query_param(url, "action") is not None):
        headers["Allow"] = "GET, POST"
        return _problem(405, headers, "Vui lòng dùng nút lưu, xóa hoặc khôi phục mặc định trên trang này.")

    export_json = method_upper == "GET" and bool(FORMAT_JSON_RE.search(url))
    storage_available = bool(storage is not None and callable(getattr(storage, "read", None)))
    engine = mapping_config.MappingConfigEngine(storage)
    config = engine.read()
    preset_catalog = engine.presets()

    response_status = 200
    action_error = ""
    form_draft: dict[str, Any] | None = None
    clear_message = ""

    if method_upper == "POST":
        origin = _get_header_single(request_headers, "origin")
        fetch_site = _get_header_single(request_headers, "sec-fetch-site")
        if (
            not isinstance(origin, str)
            or origin.lower() != "https://one.google.com"
            or (fetch_site is not None and fetch_site.lower() != "same-origin")
        ):
            return _problem(403, headers, "Vui lòng gửi thay đổi trực tiếp từ trang quản lý SKU cục bộ.")

        content_type = _get_header_single(request_headers, "content-type")
        if not isinstance(content_type, str) or not CONTENT_TYPE_RE.match(content_type):
            return _problem(415, headers, "Yêu cầu lưu phải sử dụng định dạng biểu mẫu gốc của trang.")

        if not isinstance(request_body, str):
            return _problem(400, headers, "Không nhận được nội dung biểu mẫu; vui lòng tải lại trang quản lý.")

        if len(request_body) > 20000 or len(request_body.encode("utf-8")) > 20000:
            return _problem(413, headers, "Biểu mẫu vượt quá 20KB, vui lòng lưu từng quy tắc.")

        parsed = _parse_form(request_body)
        if not parsed["ok"]:
            return _problem(400, headers, parsed["error"])

        fields: dict[str, str] = parsed["fields"]
        action = fields.get("action")
        if action not in ("upsert", "delete", "reset", "preset"):
            return _problem(400, headers, "Thao tác biểu mẫu không được hỗ trợ, vui lòng tải lại trang.")

        if action == "preset":
            if len(fields) != 3 or "revision" not in fields or "preset" not in fields:
                return _problem(400, headers, "Trường biểu mẫu mẫu nhanh không hợp lệ, vui lòng tải lại trang.")
        elif "preset" in fields:
            return _problem(400, headers, "Trường biểu mẫu không hợp lệ, vui lòng tải lại trang.")

        result, form_draft = _change_mapping(engine, config, fields)
        if result["ok"]:
            notice_map = {
                "preset": "preset",
                "reset": "reset",
                "delete": "deleted",
                "upsert": "saved",
            }
            redir_headers = dict(headers)
            redir_headers["Location"] = f"{ROOT}?notice={notice_map[action]}"
            return {"status": 303, "headers": redir_headers, "body": ""}

        response_status = result["status"]
        action_error = result["error"]
        config = engine.read()
        if response_status == 409:
            form_draft = None

    elif not export_json and CLEAR_RE.search(url):
        try:
            if storage_available and callable(getattr(storage, "write", None)):
                scan_cleared = bool(storage.write("{}", SCAN_KEY))
                test_cleared = bool(storage.write("{}", TEST_KEY))
                if scan_cleared and test_cleared:
                    # Redirect 303 so Safari reload never keeps ?clear=1 in the URL bar and re-wipes state.
                    redir_headers = dict(headers)
                    redir_headers["Location"] = f"{ROOT}?notice=cleared"
                    return {"status": 303, "headers": redir_headers, "body": ""}
                clear_message = "Xóa lịch sử thu thập và kiểm tra chưa hoàn tất."
            else:
                clear_message = "Bộ nhớ cục bộ chưa sẵn sàng để xóa lịch sử."
        except Exception:
            clear_message = "Bộ nhớ cục bộ chưa sẵn sàng để xóa lịch sử."

    scan_raw = _load_key(storage, storage_available, SCAN_KEY)
    test_raw = _load_key(storage, storage_available, TEST_KEY)

    recorded_target = _sku(test_raw.get("target"))
    if not recorded_target and LEGACY_VERSION_RE.match(str(test_raw.get("version") or "")):
        recorded_target = LEGACY_TARGET

    matched_from = _rows(test_raw.get("matchedFrom"), False, recorded_target)
    if not recorded_target and "mappingRevision" not in test_raw:
        for row in matched_from:
            if row["id"].startswith("g1.ios.2tb.") and row["to"]:
                recorded_target = row["to"]
                break

    raw_annual_hits = test_raw.get("annualHitCount")
    if isinstance(raw_annual_hits, (int, float)) and not isinstance(raw_annual_hits, bool):
        annual_hit_count = _count(raw_annual_hits)
    else:
        annual_hit_count = sum(
            row["count"] for row in matched_from if row["id"].startswith("g1.ios.2tb.")
        )

    stored_origin = _text(test_raw.get("targetOrigin"), 32)
    if recorded_target and ORIGIN_RE.match(stored_origin):
        target_origin = stored_origin
    elif recorded_target == DEFAULT_TARGET:
        target_origin = "user-specified"
    elif recorded_target == LEGACY_TARGET:
        target_origin = "legacy"
    else:
        target_origin = ""

    mapping_status_raw = test_raw.get("mappingStatus")
    mapping_status = (
        mapping_status_raw
        if mapping_status_raw in ("default", "custom", "invalid", "unavailable")
        else ""
    )

    report = {
        "schemaVersion": 1,
        "reportVersion": VERSION,
        "configuredMode": config["mode"],
        "configuredTarget": config["target"],
        "storageAvailable": storage_available,
        "mappingConfig": {
            "status": config["status"],
            "revision": config["revision"],
            "updatedAt": config["updatedAt"],
            "mode": config["mode"],
            "customized": config["customized"],
            "rules": config["rules"],
            "target": config["target"],
            "targetOrigin": config["targetOrigin"],
            "error": config["error"],
            "limit": engine.limit,
        },
        "scan": {
            "version": _text(scan_raw.get("version"), 32),
            "mode": _mode(scan_raw.get("mode")),
            "updatedAt": _text(scan_raw.get("updatedAt"), 32),
            "scannedResponses": _count(scan_raw.get("scannedResponses")),
            "matchedResponses": _count(scan_raw.get("matchedResponses")),
            "nonTextResponses": _count(scan_raw.get("nonTextResponses")),
            "recentResponses": _recent(scan_raw.get("recentResponses")),
            "truncated": scan_raw.get("truncated") is True,
            "limit": 300,
            "skus": _rows(scan_raw.get("skus"), True),
        },
        "test": {
            "version": _text(test_raw.get("version"), 32),
            "mode": _mode(test_raw.get("mode")),
            "updatedAt": _text(test_raw.get("updatedAt"), 32),
            "mappingRevision": _text(test_raw.get("mappingRevision"), 64),
            "mappingUpdatedAt": _text(test_raw.get("mappingUpdatedAt"), 32),
            "mappingStatus": mapping_status,
            "sourcePrefix": "g1.ios.2tb.",
            "target": recorded_target,
            "targetOrigin": target_origin,
            "status": _text(test_raw.get("status"), 32),
            "hitCount": _count(test_raw.get("hitCount")),
            "annualHitCount": annual_hit_count,
            "matchedFrom": matched_from,
        },
    }

    print(
        f"[g1-sku-report] {VERSION} {'json' if export_json else 'html'} "
        f"storage={'ready' if storage_available else 'unavailable'} "
        f"candidates={len(report['scan']['skus'])}"
    )

    if export_json:
        json_headers = dict(headers)
        json_headers["Content-Type"] = "application/json; charset=utf-8"
        json_headers["Content-Disposition"] = 'attachment; filename="g1-sku-report.json"'
        return {
            "status": 200,
            "headers": json_headers,
            "body": json.dumps(report, ensure_ascii=False, indent=2),
        }

    body_html = _render_html(
        url=url,
        method=method_upper,
        engine=engine,
        config=config,
        preset_catalog=preset_catalog,
        report=report,
        storage=storage,
        storage_available=storage_available,
        action_error=action_error,
        form_draft=form_draft,
        clear_message=clear_message,
    )
    return {"status": response_status, "headers": headers, "body": body_html}


def _change_mapping(
    engine: mapping_config.MappingConfigEngine,
    config: dict[str, Any],
    fields: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    action = fields["action"]
    if action == "preset":
        return engine.apply_preset(fields.get("revision"), fields.get("preset")), None
    if fields.get("revision") != config["revision"]:
        return {"ok": False, "status": 409, "error": mapping_config.REVISION_ERROR}, None
    if action == "reset":
        return engine.save(fields.get("revision"), [], True), None
    if config["status"] not in ("default", "custom"):
        return {
            "ok": False,
            "status": 503 if config["status"] == "unavailable" else 409,
            "error": "Cấu hình ánh xạ hiện chưa sẵn sàng, vui lòng khôi phục mặc định rồi chỉnh sửa lại.",
        }, None

    rule_id = fields.get("id") or ""
    rules = [dict(r) for r in config["rules"]]
    index = next((i for i, r in enumerate(rules) if r["id"] == rule_id), -1)
    if rule_id and index == -1:
        return {"ok": False, "status": 400, "error": "Quy tắc này không còn tồn tại, hãy tải lại trang."}, None

    form_draft = None
    if action == "delete":
        if index == -1:
            return {"ok": False, "status": 400, "error": "Hãy nhấn nút xóa trên quy tắc hiện có."}, None
        rules.pop(index)
    else:
        form_draft = {
            "id": rule_id,
            "match": fields.get("match") or "",
            "from": fields["from"].strip() if isinstance(fields.get("from"), str) else "",
            "to": fields["to"].strip() if isinstance(fields.get("to"), str) else "",
            "enabled": fields.get("enabled") == "1",
        }
        if "enabled" in fields and fields["enabled"] != "1":
            return {
                "ok": False,
                "status": 400,
                "error": "Trạng thái kích hoạt không hợp lệ, vui lòng chọn lại rồi lưu.",
            }, form_draft
        rule = {
            "id": rule_id or engine.new_id(),
            "match": form_draft["match"],
            "from": form_draft["from"],
            "to": form_draft["to"],
            "enabled": form_draft["enabled"],
        }
        if index < 0:
            rules.append(rule)
        else:
            rules[index] = rule

    return engine.save(fields.get("revision"), rules, False), form_draft


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _render_html(
    *,
    url: str,
    method: str,
    engine: mapping_config.MappingConfigEngine,
    config: dict[str, Any],
    preset_catalog: list[dict[str, Any]],
    report: dict[str, Any],
    storage: Any,
    storage_available: bool,
    action_error: str,
    form_draft: dict[str, Any] | None,
    clear_message: str,
) -> str:
    valid_config = config["status"] in ("default", "custom")
    writable = bool(
        storage_available and callable(getattr(storage, "write", None)) and config["status"] != "unavailable"
    )
    enabled_count = sum(1 for r in config["rules"] if r["enabled"])
    applied = (
        valid_config
        and report["test"]["version"] == COLLECTOR_VERSION
        and report["test"]["mappingRevision"] == config["revision"]
        and report["test"]["mappingUpdatedAt"] == config["updatedAt"]
        and report["test"]["mappingStatus"] == config["status"]
    )

    notices = {
        "preset": "Đã lưu mẫu ánh xạ vào máy cục bộ; quy tắc đã được bật cho phản hồi /ai? tiếp theo.",
        "saved": "Đã lưu quy tắc ánh xạ cục bộ; phản hồi trang gói tiếp theo sẽ áp dụng quy tắc mới.",
        "deleted": "Đã xóa quy tắc ánh xạ; lịch sử thu thập và kiểm tra vẫn được giữ nguyên.",
        "reset": "Đã khôi phục 3 quy tắc mặc định; lịch sử thu thập và kiểm tra vẫn được giữ nguyên.",
        "cleared": "Đã xóa toàn bộ dữ liệu thu thập và lịch sử kiểm tra; cấu hình ánh xạ vẫn được giữ nguyên.",
    }
    notice = _query_param(url, "notice")
    notice_text = ""
    if method == "GET" and notice in notices:
        if notice == "cleared" or config["updatedAt"]:
            notice_text = notices[notice]

    prefill = _query_param(url, "from")
    new_rule: dict[str, Any] = {
        "id": "",
        "match": "exact",
        "from": prefill if engine.valid_sku(prefill) else "",
        "to": "",
        "enabled": True,
    }
    orphan_draft = bool(
        form_draft and form_draft["id"] and not any(r["id"] == form_draft["id"] for r in config["rules"])
    )
    if orphan_draft and form_draft is not None:
        new_rule = {
            "id": "",
            "match": form_draft["match"],
            "from": form_draft["from"],
            "to": form_draft["to"],
            "enabled": form_draft["enabled"],
        }

    candidates: set[str] = set()
    for row in report["scan"]["skus"]:
        if engine.valid_sku(row["id"]):
            candidates.add(row["id"])
    candidate_rules = list(config["rules"]) + list(engine.defaults())
    for preset in preset_catalog:
        candidate_rules.extend(preset["rules"])
    for rule in candidate_rules:
        if engine.valid_sku(rule["from"]):
            candidates.add(rule["from"])
        if engine.valid_sku(rule["to"]):
            candidates.add(rule["to"])

    rev_input = f'<input type=hidden name=revision value="{_esc(config["revision"])}">'

    def render_presets() -> str:
        cards = []
        for preset in preset_catalog:
            matches = valid_config and all(
                any(
                    r["match"] == target["match"]
                    and r["from"] == target["from"]
                    and r["to"] == target["to"]
                    and r["enabled"]
                    for r in config["rules"]
                )
                for target in preset["rules"]
            )
            if matches and preset["id"] == "pro-1yuan":
                matches = not any(
                    r["enabled"]
                    and r["match"] == "exact"
                    and r["from"] == "g1.ios.20tb.m.v2"
                    and r["to"] == preset["rules"][0]["to"]
                    for r in config["rules"]
                )
            pairs = "".join(
                "<div class=preset-pair>"
                f"<span class=note>{'SKU đầy đủ (exact)' if r['match'] == 'exact' else 'Tiền tố SKU (prefix)'}</span>"
                f"<code>{_esc(r['from'])}</code>"
                "<span aria-label=thay-bang>↓</span>"
                f"<code>{_esc(r['to'])}</code></div>"
                for r in preset["rules"]
            )
            cards.append(
                f'<form class=preset method=post action="{ROOT}">'
                f"<fieldset{'' if (writable and valid_config) else ' disabled'}>"
                f"<legend>{_esc(preset['title'])}</legend>"
                f"{rev_input}"
                f'<input type=hidden name=preset value="{_esc(preset["id"])}">'
                f"<p class=note>{_esc(preset['description'])}</p>"
                f"{pairs}"
                + ("<p class=preset-state>Đang khớp cấu hình hiện tại</p>" if matches else "")
                + "<button class=primary type=submit name=action value=preset>Áp dụng mẫu</button>"
                "</fieldset></form>"
            )
        return (
            "<section id=mapping-presets><h2>Mẫu ánh xạ nhanh (5 bộ cài sẵn)</h2>"
            "<p>Nhấn <strong>Áp dụng mẫu</strong> để gộp và lưu ngay vào máy cục bộ; các quy tắc thủ công khác và lịch sử vẫn giữ nguyên.</p>"
            "<p class=note>Có thể dùng đồng thời <strong>1 CNY Pro</strong> và <strong>Thổ Nhĩ Kỳ 20TB / 30TB</strong>. "
            "Khi áp dụng 1 CNY Pro, quy tắc cũ <code>g1.ios.20tb.m.v2 → Gemini</code> sẽ tự tắt để tránh xung đột với 20TB.</p>"
            "<p class=note>Sau khi lưu, hãy mở lại trang gói trên Google App để phản hồi <code>/ai?</code> tiếp theo áp dụng quy tắc mới.</p>"
            f"<div class=preset-grid>{''.join(cards)}</div></section>"
        )

    def render_rule_form(rule: dict[str, Any], is_new: bool) -> str:
        draft = form_draft if (form_draft and form_draft["id"] == rule["id"]) else rule
        disabled = (not writable) or (not valid_config) or (is_new and len(config["rules"]) >= engine.limit)
        select_opts = (
            f"<option value=exact{' selected' if draft['match'] == 'exact' else ''}>SKU đầy đủ (exact)</option>"
            f"<option value=prefix{' selected' if draft['match'] == 'prefix' else ''}>Tiền tố SKU kết thúc bằng dấu chấm (prefix)</option>"
        )
        if draft["match"] not in ("exact", "prefix"):
            select_opts = '<option value="" selected>Chọn kiểu khớp</option>' + select_opts
        return (
            f'<form class=rule method=post action="{ROOT}"{" id=new-mapping" if is_new else ""}>'
            f"<fieldset{' disabled' if disabled else ''}>"
            f"<legend>{'Thêm ánh xạ mới' if is_new else 'Chỉnh sửa ánh xạ'}</legend>"
            f"{rev_input}"
            f'<input type=hidden name=id value="{_esc(rule["id"])}">'
            "<div class=fields>"
            f"<label>Kiểu khớp<select name=match required>{select_opts}</select></label>"
            f"<label class=check><input type=checkbox name=enabled value=1{' checked' if draft['enabled'] else ''}>Bật quy tắc này</label>"
            f"<label>SKU nguồn<input name=from type=text list=sku-candidates required maxlength=178 "
            r'pattern="(?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._\-]{1,160}" '
            f'autocomplete=off autocapitalize=none spellcheck=false value="{_esc(draft["from"][:300])}" '
            'placeholder="g1.ios.20tb.m.v2"></label>'
            f"<label>SKU đích<input name=to type=text list=sku-candidates required maxlength=178 "
            r'pattern="(?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._\-]{0,159}[A-Za-z0-9_\-]" '
            f'autocomplete=off autocapitalize=none spellcheck=false value="{_esc(draft["to"][:300])}" '
            'placeholder="g1.20tb.3months_ip_75p.acq"></label>'
            "</div>"
            "<div class=actions>"
            f"<button class=primary type=submit name=action value=upsert>{'Thêm và lưu' if is_new else 'Lưu quy tắc này'}</button>"
            + (
                ""
                if is_new
                else "<button class=delete type=submit name=action value=delete formnovalidate>Xóa quy tắc</button>"
            )
            + "</div></fieldset></form>"
        )

    def render_mapping_editor() -> str:
        parts = [
            "<section id=mapping-editor><h2>Quản lý ánh xạ thủ công</h2>",
            "<p>Chỉnh sửa SKU nguồn, SKU đích hoặc trạng thái bật/tắt rồi nhấn nút lưu của từng thẻ.</p>",
            f"<p><strong>Đang bật {enabled_count} / tổng {len(config['rules'])} quy tắc</strong>, tối đa {engine.limit} quy tắc.</p>",
            f"<p>Thời gian lưu cấu hình (UTC): <code>{_esc(config['updatedAt'] or 'Đang dùng mặc định tích hợp sẵn, chưa lưu thủ công')}</code></p>",
        ]
        if not valid_config:
            parts.append(f"<p class=error role=alert>{_esc(config['error'])}</p>")
        elif applied:
            parts.append(
                f"<p class=success>Lần thực thi gần nhất đã dùng cấu hình hiện tại; số lần thay thế: {report['test']['hitCount']}.</p>"
            )
        else:
            parts.append(
                "<p class=note>Đang chờ phản hồi <code>/ai?</code> tiếp theo để áp dụng cấu hình hiện tại; hãy mở lại trang gói trên Google App rồi làm mới trang này.</p>"
            )
        if report["test"]["version"] and report["test"]["version"] != COLLECTOR_VERSION:
            parts.append(
                f"<p class=note>Bản ghi thực thi gần nhất thuộc phiên bản cũ <code>{_esc(report['test']['version'])}</code>, "
                f"phiên bản hiện tại là <code>{_esc(COLLECTOR_VERSION)}</code>. Mở lại trang gói để cập nhật bản ghi mới.</p>"
            )
        if valid_config and enabled_count == 0:
            parts.append("<p class=note>Hiện không có quy tắc nào được bật: hệ thống vẫn thu thập SKU nhưng giữ nguyên phản hồi gốc.</p>")
        if not writable:
            parts.append("<p class=error>Bộ nhớ cục bộ chưa sẵn sàng để ghi; các nút chỉnh sửa tạm khóa.</p>")
        parts.append(
            "<p class=note>Ưu tiên khớp chính xác (exact), sau đó chọn tiền tố dài nhất (prefix kết thúc bằng dấu chấm). "
            "Mỗi SKU gốc chỉ thay thế 1 lần, không thay thế dây chuyền.</p>"
        )
        datalist_opts = "".join(f'<option value="{_esc(sku_id)}"></option>' for sku_id in sorted(candidates))
        parts.append(f"<datalist id=sku-candidates>{datalist_opts}</datalist>")
        for rule in config["rules"]:
            parts.append(render_rule_form(rule, False))
        if orphan_draft:
            parts.append("<p class=note>Bản nháp trước đó chưa được lưu xác nhận và đã giữ lại trong ô Thêm mới.</p>")
        parts.append(render_rule_form(new_rule, True))
        if len(config["rules"]) >= engine.limit:
            parts.append("<p class=note>Đã đạt giới hạn 30 quy tắc; hãy xóa bớt một quy tắc trước khi thêm mới.</p>")
        parts.append(
            f'<form class=reset method=post action="{ROOT}">{rev_input}'
            f"<button type=submit name=action value=reset{'' if writable else ' disabled'}>Khôi phục mặc định (3 quy tắc)</button></form>"
            "<p class=note>Khôi phục mặc định sẽ đặt lại bộ quy tắc về 2TB 12 tháng 90p và 20TB / 30TB 3 tháng 75p; lịch sử thu thập và thực thi vẫn giữ nguyên.</p></section>"
        )
        return "".join(parts)

    def render_table(items: list[dict[str, Any]], with_time: bool) -> str:
        if not items:
            return "<p>Chưa có dữ liệu.</p>"
        head = (
            "<th>Lần cuối thấy (UTC)</th><th>Dùng làm nguồn</th>"
            if with_time
            else "<th>SKU đích thực tế</th><th>Fallback</th>"
        )
        rows_html = []
        for row in items:
            tail = (
                f"<td>{_esc(row['lastSeen'])}</td>"
                f'<td><a href="{ROOT}?from={_esc(quote(row["id"], safe="~!*()\'"))}#new-mapping">Dùng làm SKU nguồn</a></td>'
                if with_time
                else f"<td><code>{_esc(row['to'] or 'Chưa ghi nhận')}</code></td><td>{_esc(_fallback_name(row))}</td>"
            )
            rows_html.append(f"<tr><td><code>{_esc(row['id'])}</code></td><td>{row['count']}</td>{tail}</tr>")
        return (
            f"<div class=scroll><table><thead><tr><th>SKU ID</th><th>Số lần</th>{head}</tr></thead>"
            f"<tbody>{''.join(rows_html)}</tbody></table></div>"
        )

    def render_recent_table(events: list[dict[str, Any]]) -> str:
        if not events:
            return "<p>Chưa có nhật ký từng phản hồi gần đây.</p>"
        rows_html = [
            "<tr>"
            f"<td>{_esc(ev['at'])}</td>"
            f"<td>{_esc(ev['path'])}</td>"
            f"<td>{_esc(SCAN_STATUSES[ev['status']])}</td>"
            f"<td>{ev['candidateCount']}</td>"
            f"<td>{ev['addedCount']}</td>"
            f"<td>{ev['omittedCount']}</td>"
            "</tr>"
            for ev in reversed(events)
        ]
        return (
            "<div class=scroll><table><thead><tr>"
            "<th>Thời gian (UTC)</th><th>Đường dẫn</th><th>Trạng thái</th><th>SKU</th><th>Mới</th><th>Bỏ qua</th>"
            f"</tr></thead><tbody>{''.join(rows_html)}</tbody></table></div>"
        )

    latest_scan = report["scan"]["recentResponses"][-1] if report["scan"]["recentResponses"] else None
    if report["scan"]["version"] == COLLECTOR_VERSION:
        scan_version_status = "Bản ghi thuộc phiên bản thu thập hiện tại."
    elif report["scan"]["version"]:
        scan_version_status = "Bản ghi thu thập từ phiên bản cũ; chưa có phản hồi mới ở bản hiện tại."
    else:
        scan_version_status = "Chưa có bản ghi thu thập ở phiên bản hiện tại."

    if config["mode"] == "discount75":
        configured_offers = "Mặc định 20TB / 30TB đang dùng Ultra 3 tháng 75p (giảm 75%), không dùng fallback."
    elif config["mode"] == "custom":
        configured_offers = "Đang dùng cấu hình ánh xạ tùy chỉnh theo các quy tắc đang bật ở trên."
    else:
        configured_offers = "Cấu hình ánh xạ chưa sẵn sàng, tạm dừng viết lại."

    statuses = {
        "rewritten": "Đã thay thế chuỗi SKU",
        "no-match": "Không khớp quy tắc nào đang bật",
        "non-text": "Phản hồi không phải văn bản",
        "config-error": "Cấu hình lỗi, giữ nguyên phản hồi gốc",
    }
    exec_status = statuses.get(report["test"]["status"], "Chưa có bản ghi thực thi")
    if report["test"]["version"] == "pro-annual-test-v1" and report["test"]["status"] == "no-match":
        exec_status = "Bản ghi v1 cũ: không khớp tiền tố iOS 2TB"

    css = (
        "*{box-sizing:border-box}"
        "body{font:16px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;max-width:960px;margin:24px auto;padding:0 18px;color:#1c2737;background:#f5f7fa}"
        "section{background:#fff;border:1px solid #dde3ec;border-radius:12px;padding:18px;margin:18px 0}"
        "h1{font-size:24px;margin-bottom:10px}h2{font-size:20px}"
        "code{overflow-wrap:anywhere}a{color:#1259be}"
        "table{border-collapse:collapse;width:100%;font-size:14px}"
        "td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}"
        ".scroll{overflow:auto}.note{color:#46556b}"
        ".badge,.success{background:#e0f4e8;color:#176238;padding:8px 12px;border-radius:8px}"
        ".badge{display:inline-block;font-weight:600}"
        ".error{background:#fff0ef;color:#9b2420;padding:12px;border-radius:8px;overflow-wrap:anywhere}"
        ".actions{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:18px 0}"
        ".actions form{margin:0}"
        "button,.actions a{font:inherit;padding:10px 16px;border:0;border-radius:8px;cursor:pointer;text-decoration:none}"
        ".actions a,button{background:#e4eaf3;color:#1c2737}"
        ".primary{background:#1259be;color:#fff}.delete{background:#fff0ef;color:#9b2420}"
        "fieldset{min-width:0;margin:0;border:1px solid #d7e0ec;border-radius:10px;padding:16px}"
        "legend{font-weight:600;padding:0 6px}.rule{margin:20px 0}"
        ".fields{display:grid;grid-template-columns:1fr 1fr;gap:16px}.fields label{font-weight:600;min-width:0}"
        "input[type=text],select{font:16px/1.4 -apple-system,BlinkMacSystemFont,sans-serif;width:100%;padding:12px;margin-top:6px;border:1px solid #a7b5c8;border-radius:7px;background:#fff;color:#1c2737}"
        "input[type=text]{font-family:ui-monospace,SFMono-Regular,monospace}"
        ".check{display:flex;align-items:center;gap:10px;align-self:end;min-height:48px}.check input{width:20px;height:20px}"
        ".rule .actions{margin-bottom:0}button:disabled,fieldset:disabled{opacity:.55}button:disabled{cursor:default}"
        ".reset{margin-top:24px}"
        ".preset-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}"
        ".preset{min-width:0;margin:0}.preset fieldset{height:100%;display:flex;flex-direction:column}"
        ".preset legend{max-width:100%;font-size:16px}.preset .note{font-size:14px}"
        ".preset-pair{padding:10px;margin:12px 0;background:#f5f7fa;border-radius:6px}"
        ".preset-pair code{display:block;font-size:13px;line-height:1.6}"
        ".preset-state{align-self:flex-start;font-size:13px;padding:5px 8px;margin:0 0 12px;background:#e0f4e8;color:#176238;border-radius:6px}"
        ".preset button{width:100%;margin-top:auto}"
        "@media(max-width:600px){body{padding:0 10px;margin:16px auto}section{padding:14px}fieldset{padding:12px}.fields,.preset-grid{grid-template-columns:1fr}.actions{gap:8px}button{padding:10px 12px}}"
    )

    parts = [
        "<!doctype html><html lang=vi><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1"><title>Google One SKU Manager (mitmproxy)</title>',
        f"<style>{css}</style>",
        "<h1>Google One SKU Manager</h1>",
        f"<p class=badge>mitmproxy cục bộ đang hoạt động · {_esc(VERSION)}</p>",
        f"<p><strong>Chế độ cấu hình hiện tại: {_esc(_mode_name(report['configuredMode']))}</strong></p>",
        f'<nav class=actions aria-label="Thao tác báo cáo"><form method=get action="{ROOT}"><button type=submit name=format value=json>Tải JSON</button></form><a href="{ROOT}">Làm mới</a></nav>',
        "<p class=note>Trang này được phục vụ cục bộ bởi mitmproxy trên Windows; cấu hình ánh xạ và lịch sử thu thập lưu tại máy tính.</p>",
        f"<p class=error role=alert>{_esc(action_error)}</p>" if action_error else "",
        f"<p class=success role=status>{_esc(notice_text)}</p>" if notice_text else "",
        f"<p>{_esc(clear_message)}</p>" if clear_message else "",
        "" if storage_available else "<p>Bộ nhớ cục bộ chưa sẵn sàng; chưa thể đọc lịch sử thu thập.</p>",
        render_presets(),
        render_mapping_editor(),
        "<section><h2>Thống kê thu thập</h2>",
        f"<p>Phiên bản thu thập thực tế: <code>{_esc(report['scan']['version'] or 'Chưa có')}</code><br>"
        f"Chế độ thu thập thực tế: {_esc(_mode_name(report['scan']['mode']))}<br>{_esc(scan_version_status)}</p>",
        f"<p>Text responses: {report['scan']['scannedResponses']} | Non-text: {report['scan']['nonTextResponses']} | "
        f"Có SKU: {report['scan']['matchedResponses']} | Tổng ID: {len(report['scan']['skus'])}</p>",
        f"<p>Cập nhật (UTC): <code>{_esc(report['scan']['updatedAt'] or 'Chưa có')}</code></p>",
        (
            f"<p><strong>Phản hồi gần nhất: {_esc(SCAN_STATUSES[latest_scan['status']])}</strong><br>"
            f"Nhận diện {latest_scan['candidateCount']} SKU khác nhau, thêm mới {latest_scan['addedCount']}, "
            f"vượt giới hạn {latest_scan['omittedCount']}.</p>"
            if latest_scan
            else ""
        ),
        "<h3>10 phản hồi gần nhất</h3>",
        render_recent_table(report["scan"]["recentResponses"]),
        "</section>",
        "<section><h2>Kết quả ánh xạ gần nhất (/ai?)</h2>",
        f"<p>Đích tiền tố 2TB đang cấu hình: <code>{_esc(report['configuredTarget'] or 'Không bật quy tắc tiền tố 2TB')}</code></p>",
        f"<p>Phiên bản: <code>{_esc(report['test']['version'] or 'Chưa có')}</code><br>"
        f"Chế độ thực thi: {_esc(_mode_name(report['test']['mode']))}<br>"
        f"Trạng thái: <strong>{_esc(exec_status)}</strong> | Tổng hit: {report['test']['hitCount']} | Trong đó 2TB: {report['test']['annualHitCount']}</p>",
        f"<p>Đích 2TB đã ghi nhận: <code>{_esc(report['test']['target'] or 'Chưa có')}</code><br>{_esc(configured_offers)}<br>"
        f"Thời gian cấu hình dùng khi chạy (UTC): <code>{_esc(report['test']['mappingUpdatedAt'] or 'Mặc định / bản cũ')}</code><br>"
        f"Thời gian thực thi (UTC): <code>{_esc(report['test']['updatedAt'] or 'Chưa có')}</code></p>",
        render_table(report["test"]["matchedFrom"], False),
        "</section>",
        "<section><h2>Danh sách SKU gốc đã thu thập</h2>",
        f"<p>Tổng SKU đã lưu: {len(report['scan']['skus'])} (tối đa 300). Nhấn <em>Dùng làm SKU nguồn</em> để điền sẵn vào khung thêm quy tắc.</p>",
        "<p>Danh sách đã đạt giới hạn 300 SKU; xóa lịch sử thu thập để ghi mới.</p>" if report["scan"]["truncated"] else "",
        render_table(report["scan"]["skus"], True),
        f"<p>Cập nhật (UTC): <code>{_esc(report['scan']['updatedAt'] or 'Chưa có')}</code></p></section>",
        f'<form method=get action="{ROOT}"><button name=clear value=1>Xóa lịch sử thu thập & kiểm tra</button></form>',
        "<p class=note>Thao tác xóa chỉ xóa dữ liệu thu thập và lịch sử thực thi; các quy tắc ánh xạ vẫn được giữ nguyên.</p></html>",
    ]
    return "".join(parts)
