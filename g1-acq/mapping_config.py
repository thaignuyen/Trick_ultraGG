"""Shared local mapping configuration engine ported from crhywun/g1-acq (v7.12.0)."""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any

KEY = "g1.sku.mappings.v1"
LIMIT = 30
DEFAULT_REVISION = "defaults-75p-v1"
SOURCE_PREFIX = "g1.ios.2tb."

READ_ERROR = "Bộ nhớ cấu hình ánh xạ cục bộ chưa sẵn sàng; phản hồi lần này được giữ nguyên."
CONFIG_ERROR = "Định dạng cấu hình ánh xạ bị lỗi, tạm dừng viết lại; vui lòng khôi phục mặc định rồi chỉnh sửa lại."
WRITE_ERROR = "Không xác minh được dữ liệu sau khi lưu; hãy tải lại trang để kiểm tra cấu hình hiện tại."
REVISION_ERROR = "Cấu hình đã thay đổi trước khi lưu; trang đã tải quy tắc mới nhất, vui lòng thao tác lại."

RULE_FIELDS = ("id", "match", "from", "to", "enabled")
RECORD_FIELDS = ("schemaVersion", "revision", "updatedAt", "customized", "rules")

VALID_SKU_RE = re.compile(
    r"\A(?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._-]{0,159}[A-Za-z0-9_-]\Z"
)
VALID_PREFIX_RE = re.compile(
    r"\A(?:g1\.|com\.google\.(?:one|gemini)\.)[A-Za-z0-9._-]{1,159}\.\Z"
)
VALID_RULE_ID_RE = re.compile(r"\A[a-z][a-z0-9-]{0,39}\Z")
REVISION_HEX_RE = re.compile(r"\A[a-f0-9]{48}\Z")
VALID_TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")


def utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def defaults() -> list[dict[str, Any]]:
    """Return the built-in default ruleset for discount75 mode."""
    return [
        {
            "id": "default-2tb",
            "match": "prefix",
            "from": SOURCE_PREFIX,
            "to": "g1.2tb.ai.12months_ip_90p",
            "enabled": True,
        },
        {
            "id": "default-20tb",
            "match": "exact",
            "from": "g1.ios.20tb.m.v2",
            "to": "g1.20tb.3months_ip_75p.acq",
            "enabled": True,
        },
        {
            "id": "default-30tb",
            "match": "exact",
            "from": "g1.ios.30tb.ai.pro.m",
            "to": "g1.ai.ultra.3months_ip_75p.acq",
            "enabled": True,
        },
    ]


def presets() -> list[dict[str, Any]]:
    """Return the five built-in one-click mapping preset templates."""
    return [
        {
            "id": "pro-1yuan",
            "title": "1 Nhân dân tệ mở Pro (3 tháng đầu ~1 CNY/tháng)",
            "description": (
                "Dùng tiền tố 2TB của chính gói Pro; sau khi áp dụng hãy mở lại trang gói Pro, "
                "giá và chu kỳ thực tế xem trên App Store."
            ),
            "rules": [
                {
                    "match": "prefix",
                    "from": SOURCE_PREFIX,
                    "to": "com.google.gemini.2tb.ai.m.3month_ip_99p",
                    "enabled": True,
                }
            ],
        },
        {
            "id": "tr-ultra-20tb",
            "title": "Thổ Nhĩ Kỳ 20TB · bản ghi 1989.99 TRY",
            "description": (
                "Mã iOS 20TB cũ; bản ghi công khai là 1989.99 TRY, giá và chu kỳ thực tế xem trên App Store."
            ),
            "rules": [
                {
                    "match": "exact",
                    "from": "g1.ios.20tb.m.v2",
                    "to": "g1.ios.20tb.m",
                    "enabled": True,
                }
            ],
        },
        {
            "id": "tr-ultra-30tb",
            "title": "Thổ Nhĩ Kỳ 30TB · bản ghi 2949.99 TRY",
            "description": (
                "Mã iOS 30TB cũ; bản ghi công khai từng gọi giá 2949.99 TRY, giá và chu kỳ thực tế xem trên App Store."
            ),
            "rules": [
                {
                    "match": "exact",
                    "from": "g1.ios.30tb.ai.pro.m",
                    "to": "g1.ios.30tb.m",
                    "enabled": True,
                }
            ],
        },
        {
            "id": "ultra-75p",
            "title": "Ultra 20TB / 30TB · 3 tháng 75p",
            "description": (
                "Chuyển đồng thời 20TB và 30TB sang đích 75p hiện tại; 75p nghĩa là giảm 75%, trả 25%."
            ),
            "rules": [
                {
                    "match": "exact",
                    "from": "g1.ios.20tb.m.v2",
                    "to": "g1.20tb.3months_ip_75p.acq",
                    "enabled": True,
                },
                {
                    "match": "exact",
                    "from": "g1.ios.30tb.ai.pro.m",
                    "to": "g1.ai.ultra.3months_ip_75p.acq",
                    "enabled": True,
                },
            ],
        },
        {
            "id": "pro-12months-90p",
            "title": "2TB / Pro · 12 tháng 90p",
            "description": (
                "Dùng tiền tố 2TB hiện tại và đích ưu đãi 12 tháng; chu kỳ hiển thị theo bảng thanh toán App Store."
            ),
            "rules": [
                {
                    "match": "prefix",
                    "from": SOURCE_PREFIX,
                    "to": "g1.2tb.ai.12months_ip_90p",
                    "enabled": True,
                }
            ],
        },
    ]


def valid_sku(value: Any) -> bool:
    """Return True if value is a valid complete SKU across g1, one, or gemini namespaces."""
    return isinstance(value, str) and bool(VALID_SKU_RE.match(value))


def valid_prefix(value: Any) -> bool:
    """Return True if value is a valid dot-terminated SKU prefix."""
    return isinstance(value, str) and bool(VALID_PREFIX_RE.match(value))


def _has_fields(value: Any, fields: tuple[str, ...], allow_extra: bool = False) -> bool:
    if not isinstance(value, dict):
        return False
    if not allow_extra and len(value) != len(fields):
        return False
    return all(field in value for field in fields)


def _valid_time(value: Any) -> bool:
    if not isinstance(value, str) or not VALID_TIME_RE.match(value):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        formatted = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return formatted == value
    except Exception:
        return False


def _invalid_rules(error: str) -> dict[str, Any]:
    return {"ok": False, "rules": [], "error": error}


def validate_rules(value: Any) -> dict[str, Any]:
    """Validate and normalize a list of up to 30 mapping rules."""
    if not isinstance(value, list) or len(value) > LIMIT:
        return _invalid_rules("Ánh xạ cần danh sách quy tắc, tối đa 30 mục.")

    rules: list[dict[str, Any]] = []
    ids: set[str] = set()
    sources: set[str] = set()
    for rule in value:
        if (
            not _has_fields(rule, RULE_FIELDS)
            or not isinstance(rule["id"], str)
            or not VALID_RULE_ID_RE.match(rule["id"])
            or rule["match"] not in ("exact", "prefix")
            or not (valid_sku(rule["from"]) if rule["match"] == "exact" else valid_prefix(rule["from"]))
            or not valid_sku(rule["to"])
            or not isinstance(rule["enabled"], bool)
        ):
            return _invalid_rules(
                "Vui lòng nhập SKU đầy đủ; tiền tố phải kết thúc bằng dấu chấm, đích phải thuộc g1., com.google.one. hoặc com.google.gemini."
            )
        if rule["from"] == rule["to"]:
            return _invalid_rules("SKU nguồn và SKU đích trùng nhau, vui lòng nhập đích khác.")
        if rule["id"] in ids:
            return _invalid_rules("ID quy tắc bị trùng, vui lòng tải lại trang quản lý rồi thử lại.")
        source = f"{rule['match']}:{rule['from']}"
        if source in sources:
            return _invalid_rules("SKU nguồn với kiểu khớp này đã tồn tại, hãy sửa quy tắc hiện có.")
        ids.add(rule["id"])
        sources.add(source)
        rules.append(
            {
                "id": rule["id"],
                "match": rule["match"],
                "from": rule["from"],
                "to": rule["to"],
                "enabled": rule["enabled"],
            }
        )
    return {"ok": True, "rules": rules, "error": ""}


def new_id() -> str:
    """Generate a stable random local rule identifier."""
    return "rule-" + secrets.token_hex(8)


def _config_state(
    status: str,
    revision: str,
    updated_at: str,
    customized: bool,
    rules: list[dict[str, Any]],
    error: str,
) -> dict[str, Any]:
    target = ""
    for rule in rules:
        if rule["enabled"] and rule["match"] == "prefix" and rule["from"] == SOURCE_PREFIX:
            target = rule["to"]
            break
    mode = "discount75" if status == "default" else ("custom" if status == "custom" else "")
    target_origin = ("user-configured" if customized else "user-specified") if target else ""
    return {
        "status": status,
        "revision": revision,
        "updatedAt": updated_at,
        "mode": mode,
        "customized": customized,
        "rules": rules,
        "target": target,
        "targetOrigin": target_origin,
        "error": error,
    }


def _failed_state(status: str) -> dict[str, Any]:
    return _config_state(
        status,
        status,
        "",
        False,
        [],
        CONFIG_ERROR if status == "invalid" else READ_ERROR,
    )


def _save_result(status: int, error: str, config: dict[str, Any]) -> dict[str, Any]:
    return {"ok": status == 200, "status": status, "error": error, "config": config}


class MappingConfigEngine:
    """Mapping configuration controller backed by a $persistentStore-compatible store."""

    key = KEY
    limit = LIMIT

    def __init__(self, store: Any) -> None:
        self.store = store

    @staticmethod
    def defaults() -> list[dict[str, Any]]:
        return defaults()

    @staticmethod
    def presets() -> list[dict[str, Any]]:
        return presets()

    @staticmethod
    def valid_sku(value: Any) -> bool:
        return valid_sku(value)

    @staticmethod
    def valid_prefix(value: Any) -> bool:
        return valid_prefix(value)

    @staticmethod
    def validate_rules(value: Any) -> dict[str, Any]:
        return validate_rules(value)

    @staticmethod
    def new_id() -> str:
        return new_id()

    def read(self) -> dict[str, Any]:
        """Read and validate the persisted mapping configuration."""
        try:
            if not self.store or not callable(getattr(self.store, "read", None)):
                return _failed_state("unavailable")
            raw = self.store.read(KEY)
        except Exception:
            return _failed_state("unavailable")

        if raw is None or raw == "":
            return _config_state("default", DEFAULT_REVISION, "", False, defaults(), "")

        try:
            if not isinstance(raw, str):
                return _failed_state("invalid")
            saved = json.loads(raw)
            schema_ver = saved.get("schemaVersion") if isinstance(saved, dict) else None
            if (
                not _has_fields(saved, RECORD_FIELDS, allow_extra=True)
                or isinstance(schema_ver, bool)
                or schema_ver != 1
                or not isinstance(saved["revision"], str)
                or not REVISION_HEX_RE.match(saved["revision"])
                or not _valid_time(saved["updatedAt"])
                or not isinstance(saved["customized"], bool)
            ):
                return _failed_state("invalid")
            checked = validate_rules(saved["rules"])
            if not checked["ok"] or (not saved["customized"] and len(checked["rules"]) != 0):
                return _failed_state("invalid")
            return _config_state(
                "custom" if saved["customized"] else "default",
                saved["revision"],
                saved["updatedAt"],
                saved["customized"],
                checked["rules"] if saved["customized"] else defaults(),
                "",
            )
        except Exception:
            return _failed_state("invalid")

    def save(self, expected_revision: Any, rules: Any, restore: bool = False) -> dict[str, Any]:
        """Atomically persist rules after revision check, validation, and readback verification."""
        current = self.read()
        if current["status"] == "unavailable":
            return _save_result(503, READ_ERROR, current)
        if not isinstance(expected_revision, str) or expected_revision != current["revision"]:
            return _save_result(409, REVISION_ERROR, current)
        if current["status"] == "invalid" and restore is not True:
            return _save_result(400, CONFIG_ERROR, current)

        checked = {"ok": True, "rules": [], "error": ""} if restore is True else validate_rules(rules)
        if not checked["ok"]:
            return _save_result(400, checked["error"], current)

        try:
            if not self.store or not callable(getattr(self.store, "write", None)):
                return _save_result(503, WRITE_ERROR, current)
        except Exception:
            return _save_result(503, WRITE_ERROR, current)

        revision = secrets.token_hex(24)
        if revision == current["revision"]:
            last_digit = (int(revision[-1], 16) + 1) % 16
            revision = revision[:-1] + format(last_digit, "x")

        saved = {
            "schemaVersion": 1,
            "revision": revision,
            "updatedAt": utc_now(),
            "customized": restore is not True,
            "rules": checked["rules"],
        }
        written = False
        try:
            written = bool(self.store.write(json.dumps(saved, ensure_ascii=False), KEY))
        except Exception:
            written = False

        verified = self.read()
        expected_rules = saved["rules"] if saved["customized"] else defaults()
        expected_status = "custom" if saved["customized"] else "default"
        if (
            not written
            or verified["status"] != expected_status
            or verified["revision"] != saved["revision"]
            or verified["updatedAt"] != saved["updatedAt"]
            or verified["customized"] != saved["customized"]
            or verified["rules"] != expected_rules
        ):
            return _save_result(503, WRITE_ERROR, verified)
        return _save_result(200, "", verified)

    def apply_preset(self, expected_revision: Any, preset_id: Any) -> dict[str, Any]:
        """Merge a built-in preset into existing rules and save atomically."""
        current = self.read()
        if current["status"] == "unavailable":
            return _save_result(503, READ_ERROR, current)
        if not isinstance(expected_revision, str) or expected_revision != current["revision"]:
            return _save_result(409, REVISION_ERROR, current)
        if current["status"] == "invalid":
            return _save_result(400, CONFIG_ERROR, current)

        selected = next((p for p in presets() if p["id"] == preset_id), None)
        if selected is None:
            return _save_result(400, "Mẫu ánh xạ không tồn tại, vui lòng tải lại trang rồi thử lại.", current)

        rules = [dict(r) for r in current["rules"]]
        ids: set[str] = set()
        positions: dict[str, int] = {}
        for index, rule in enumerate(rules):
            ids.add(rule["id"])
            positions[f"{rule['match']}:{rule['from']}"] = index
            # Retire only the legacy Pro template's 20TB route in the same atomic save.
            if (
                preset_id == "pro-1yuan"
                and rule["match"] == "exact"
                and rule["from"] == "g1.ios.20tb.m.v2"
                and rule["to"] == selected["rules"][0]["to"]
                and rule["enabled"]
            ):
                rules[index] = {
                    "id": rule["id"],
                    "match": rule["match"],
                    "from": rule["from"],
                    "to": rule["to"],
                    "enabled": False,
                }

        for target_rule in selected["rules"]:
            source = f"{target_rule['match']}:{target_rule['from']}"
            if source in positions:
                pos = positions[source]
                rule_id = rules[pos]["id"]
                rules[pos] = {
                    "id": rule_id,
                    "match": target_rule["match"],
                    "from": target_rule["from"],
                    "to": target_rule["to"],
                    "enabled": True,
                }
            else:
                base = new_id()
                rule_id = base
                suffix = 1
                while rule_id in ids and suffix <= len(rules):
                    rule_id = f"{base}-{suffix}"
                    suffix += 1
                ids.add(rule_id)
                positions[source] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "match": target_rule["match"],
                        "from": target_rule["from"],
                        "to": target_rule["to"],
                        "enabled": True,
                    }
                )

        checked = validate_rules(rules)
        if not checked["ok"]:
            return _save_result(400, checked["error"], current)
        return self.save(expected_revision, checked["rules"], False)

    @staticmethod
    def resolve(sku_id: Any, state: dict[str, Any] | None) -> dict[str, Any] | None:
        """Resolve a single SKU token against active rules (exact wins over longest prefix)."""
        if (
            not valid_sku(sku_id)
            or not isinstance(state, dict)
            or state.get("status") not in ("default", "custom")
            or not isinstance(state.get("rules"), list)
        ):
            return None

        selected = None
        for rule in state["rules"]:
            if not rule.get("enabled"):
                continue
            if rule["match"] == "exact" and rule["from"] == sku_id:
                return rule
            if (
                rule["match"] == "prefix"
                and len(sku_id) > len(rule["from"])
                and sku_id.startswith(rule["from"])
                and (selected is None or len(rule["from"]) > len(selected["from"]))
            ):
                selected = rule
        return selected
