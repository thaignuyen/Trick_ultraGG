"""Comprehensive tests for g1-acq v7.12.0 mitmproxy port."""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from typing import Any
from urllib.parse import urlencode

from mitmproxy import http
from mitmproxy.test import tflow

import g1_acq_mitm
import g1_sku_report
import mapping_config

ORIGIN = "https://one.google.com"
REPORT = "https://one.google.com/g1-sku-report"
FORM_HEADERS = {
    "Origin": ORIGIN,
    "Sec-Fetch-Site": "same-origin",
    "Content-Type": "application/x-www-form-urlencoded",
}

TARGET = "g1.2tb.ai.12months_ip_90p"
TWENTY = "g1.ios.20tb.m.v2"
THIRTY = "g1.ios.30tb.ai.pro.m"
GEMINI_PRO_TARGET = "com.google.gemini.2tb.ai.m.3month_ip_99p"


class MemoryStore:
    """In-memory $persistentStore mock for deterministic testing."""

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self.data: dict[str, str] = dict(initial or {})
        self.writes: list[str] = []
        self.fail_write = False
        self.fail_read = False

    def read(self, key: str) -> str | None:
        if self.fail_read:
            raise RuntimeError("read failure")
        return self.data.get(key)

    def write(self, value: str, key: str) -> bool:
        self.writes.append(key)
        if self.fail_write:
            return False
        self.data[key] = value
        return True


def make_flow(
    url: str = "https://one.google.com/ai?utm_campaign=TEST",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    req_body: bytes | str | None = None,
    resp_body: bytes | str | None = None,
    resp_ct: str = "text/html; charset=utf-8",
) -> http.HTTPFlow:
    flow = tflow.tflow(resp=resp_body is not None)
    flow.request = http.Request.make(
        method,
        url,
        req_body if req_body is not None else b"",
        headers or {},
    )
    if resp_body is not None:
        raw = resp_body.encode("utf-8") if isinstance(resp_body, str) else resp_body
        flow.response = http.Response.make(200, raw, {"content-type": resp_ct})
    else:
        flow.response = None
    return flow


def get_json(store: Any) -> dict[str, Any]:
    flow = make_flow(url=REPORT + "?format=json")
    g1_acq_mitm.process_request(flow, store)
    assert flow.response is not None
    assert flow.response.status_code == 200
    return json.loads(flow.response.get_text(strict=True))


def post_form(
    store: Any,
    fields: dict[str, str],
    headers: dict[str, str] | None = None,
    raw_body: str | None = None,
) -> http.HTTPFlow:
    body = raw_body if raw_body is not None else urlencode(fields)
    flow = make_flow(
        url=REPORT,
        method="POST",
        headers=FORM_HEADERS if headers is None else headers,
        req_body=body,
    )
    g1_acq_mitm.process_request(flow, store)
    assert flow.response is not None
    return flow


class G1AcqMitmTests(unittest.TestCase):
    def test_defaults_and_boundary_matching(self) -> None:
        store = MemoryStore()
        src = "g1.ios.2tb.a.12month_ip_10p"
        untouched = [
            "g1.ios.12tb.fixture",
            f"{TWENTY}.extra",
            f"{THIRTY}.extra",
            "g1.ios.2tbx.fixture",
            "g1.ios.2tb.",
            f"prefix{src}",
            f"x.{src}",
            f"person@{src}",
            f"%{src}",
            f"-{src}",
            f"_{src}",
            f"{TWENTY}_extra",
            f"{THIRTY}-extra",
            "g1.2tb",
            TARGET,
        ]
        payload = [src, TWENTY, THIRTY, *untouched]
        flow = make_flow(resp_body=json.dumps(payload))
        g1_acq_mitm.process_response(flow, store)
        assert flow.response is not None
        self.assertEqual(
            json.loads(flow.response.get_text(strict=True)),
            [TARGET, "g1.20tb.3months_ip_75p.acq", "g1.ai.ultra.3months_ip_75p.acq", *untouched],
        )
        rep = get_json(store)
        self.assertEqual(rep["configuredMode"], "discount75")
        self.assertEqual(rep["configuredTarget"], TARGET)
        self.assertEqual(rep["test"]["version"], g1_acq_mitm.VERSION)
        self.assertEqual(rep["test"]["hitCount"], 3)
        self.assertEqual(rep["test"]["annualHitCount"], 1)
        self.assertEqual(rep["test"]["status"], "rewritten")
        self.assertTrue(all(row["fallback"] is False for row in rep["test"]["matchedFrom"]))

    def test_user_log_skus_and_presets_coexistence(self) -> None:
        store = MemoryStore()
        # Exact 12 SKUs observed in user's mitmproxy log.
        user_skus = [
            "g1.ios.100gb.a.1year_ip_5p",
            "g1.ios.100gb.m.1month_ip_75p",
            "g1.ios.20tb.m.v2",
            "g1.ios.2tb.a.12month_ip_10p",
            "g1.ios.2tb.m.3month_ip_75p",
            "g1.ios.30gb.a.1year_ip_5p",
            "g1.ios.30gb.m.1month_ip_75p",
            "g1.ios.30tb.ai.pro.m",
            "g1.ios.ai.2tb.a.ip_1yr_10p.acq",
            "g1.ios.ai.2tb.m.ip_3mo_75p.acq",
            "g1.ios.helium.a.ip_1yr_10p.acq",
            "g1.ios.helium.m.3month_ip_75p.acq",
        ]

        # Seed a legacy exact 20TB -> Gemini rule by editing default-20tb, then apply pro-1yuan and tr-ultra-20tb.
        rep = get_json(store)
        rev = rep["mappingConfig"]["revision"]
        # Duplicate (match, from) with empty id must be rejected with 400.
        dup = post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "exact",
                "from": TWENTY,
                "to": GEMINI_PRO_TARGET,
                "enabled": "1",
            },
        )
        self.assertEqual(dup.response.status_code, 400)

        res = post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "default-20tb",
                "match": "exact",
                "from": TWENTY,
                "to": GEMINI_PRO_TARGET,
                "enabled": "1",
            },
        )
        self.assertEqual(res.response.status_code, 303)

        rep = get_json(store)
        res = post_form(
            store,
            {"action": "preset", "revision": rep["mappingConfig"]["revision"], "preset": "pro-1yuan"},
        )
        self.assertEqual(res.response.status_code, 303)
        self.assertEqual(res.response.headers["Location"], f"{REPORT}?notice=preset")

        rep = get_json(store)
        rules = {f"{r['match']}:{r['from']}": r for r in rep["mappingConfig"]["rules"]}
        self.assertEqual(rules["prefix:g1.ios.2tb."]["to"], GEMINI_PRO_TARGET)
        self.assertTrue(rules["prefix:g1.ios.2tb."]["enabled"])
        self.assertFalse(rules[f"exact:{TWENTY}"]["enabled"])

        # Apply tr-ultra-20tb and tr-ultra-30tb alongside pro-1yuan.
        res = post_form(
            store,
            {"action": "preset", "revision": rep["mappingConfig"]["revision"], "preset": "tr-ultra-20tb"},
        )
        self.assertEqual(res.response.status_code, 303)
        rep = get_json(store)
        res = post_form(
            store,
            {"action": "preset", "revision": rep["mappingConfig"]["revision"], "preset": "tr-ultra-30tb"},
        )
        self.assertEqual(res.response.status_code, 303)

        flow = make_flow(resp_body=json.dumps(user_skus))
        g1_acq_mitm.process_response(flow, store)
        rewritten = json.loads(flow.response.get_text(strict=True))
        self.assertEqual(rewritten[2], "g1.ios.20tb.m")
        self.assertEqual(rewritten[3], GEMINI_PRO_TARGET)
        self.assertEqual(rewritten[4], GEMINI_PRO_TARGET)
        self.assertEqual(rewritten[7], "g1.ios.30tb.m")

        # Original 12 SKUs must be preserved in scan list without targets polluting it.
        rep = get_json(store)
        self.assertEqual([r["id"] for r in rep["scan"]["skus"]], sorted(user_skus))
        self.assertEqual(rep["test"]["mappingRevision"], rep["mappingConfig"]["revision"])
        self.assertEqual(rep["test"]["annualHitCount"], 2)
        self.assertEqual(rep["test"]["hitCount"], 4)

    def test_exact_beats_prefix_longest_prefix_and_single_pass(self) -> None:
        store = MemoryStore()
        rev = get_json(store)["mappingConfig"]["revision"]
        # Add chain candidate and narrower prefix.
        post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "exact",
                "from": "g1.ios.2tb.special",
                "to": "com.google.gemini.special.target",
                "enabled": "1",
            },
        )
        rev = get_json(store)["mappingConfig"]["revision"]
        post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "prefix",
                "from": "g1.ios.2tb.sub.",
                "to": "com.google.one.sub_target",
                "enabled": "1",
            },
        )
        rev = get_json(store)["mappingConfig"]["revision"]
        post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "exact",
                "from": "com.google.one.sub_target",
                "to": "g1.should_not_chain",
                "enabled": "1",
            },
        )

        body = json.dumps(["g1.ios.2tb.special", "g1.ios.2tb.sub.item", "g1.ios.2tb.other"])
        flow = make_flow(resp_body=body)
        g1_acq_mitm.process_response(flow, store)
        self.assertEqual(
            json.loads(flow.response.get_text(strict=True)),
            [
                "com.google.gemini.special.target",
                "com.google.one.sub_target",
                TARGET,
            ],
        )

    def test_178_char_gemini_boundary(self) -> None:
        store = MemoryStore()
        rev = get_json(store)["mappingConfig"]["revision"]
        gemini_178 = "com.google.gemini." + ("a" * 160)
        gemini_179 = "com.google.gemini." + ("a" * 161)
        self.assertEqual(len(gemini_178), 178)
        res = post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "exact",
                "from": "g1.ios.ai.2tb.a.ip_1yr_10p.acq",
                "to": gemini_178,
                "enabled": "1",
            },
        )
        self.assertEqual(res.response.status_code, 303)

        rev = get_json(store)["mappingConfig"]["revision"]
        bad = post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "exact",
                "from": "g1.ios.ai.2tb.m.ip_3mo_75p.acq",
                "to": gemini_179,
                "enabled": "1",
            },
        )
        self.assertEqual(bad.response.status_code, 400)

    def test_thirty_rule_limit_and_atomic_preset_failure(self) -> None:
        store = MemoryStore()
        for idx in range(27):
            rev = get_json(store)["mappingConfig"]["revision"]
            res = post_form(
                store,
                {
                    "action": "upsert",
                    "revision": rev,
                    "id": "",
                    "match": "exact",
                    "from": f"g1.extra.sku.{idx}",
                    "to": f"g1.extra.target.{idx}",
                    "enabled": "1",
                },
            )
            self.assertEqual(res.response.status_code, 303)

        rep = get_json(store)
        self.assertEqual(len(rep["mappingConfig"]["rules"]), 30)
        rev = rep["mappingConfig"]["revision"]

        # Updating an existing source via preset succeeds at 30 rules.
        res_ok = post_form(store, {"action": "preset", "revision": rev, "preset": "pro-1yuan"})
        self.assertEqual(res_ok.response.status_code, 303)

        # Adding a 31st rule fails atomically.
        rev = get_json(store)["mappingConfig"]["revision"]
        res_fail = post_form(
            store,
            {
                "action": "upsert",
                "revision": rev,
                "id": "",
                "match": "exact",
                "from": "g1.extra.sku.31",
                "to": "g1.extra.target.31",
                "enabled": "1",
            },
        )
        self.assertEqual(res_fail.response.status_code, 400)
        self.assertEqual(len(get_json(store)["mappingConfig"]["rules"]), 30)

    def test_security_headers_conflict_and_storage_errors(self) -> None:
        store = MemoryStore()
        rev = get_json(store)["mappingConfig"]["revision"]

        # GET with action= returns 405
        f_get = make_flow(url=REPORT + "?action=reset", method="GET")
        g1_acq_mitm.process_request(f_get, store)
        self.assertEqual(f_get.response.status_code, 405)
        self.assertEqual(f_get.response.headers["Allow"], "GET, POST")

        # Bad origin -> 403
        f_origin = post_form(
            store,
            {"action": "reset", "revision": rev},
            headers={"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(f_origin.response.status_code, 403)

        # Bad content-type -> 415
        f_ct = post_form(
            store,
            {"action": "reset", "revision": rev},
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        )
        self.assertEqual(f_ct.response.status_code, 415)

        # Bad percent encoding -> 400
        f_enc = post_form(store, {}, raw_body="action=reset&revision=%ZZ")
        self.assertEqual(f_enc.response.status_code, 400)

        # Stale revision -> 409
        post_form(store, {"action": "preset", "revision": rev, "preset": "pro-1yuan"})
        f_stale = post_form(store, {"action": "preset", "revision": rev, "preset": "tr-ultra-20tb"})
        self.assertEqual(f_stale.response.status_code, 409)

        # Write failure -> 503
        store.fail_write = True
        rev2 = get_json(store)["mappingConfig"]["revision"]
        f_503 = post_form(store, {"action": "preset", "revision": rev2, "preset": "tr-ultra-20tb"})
        self.assertEqual(f_503.response.status_code, 503)
        store.fail_write = False

    def test_clear_redirects_and_preserves_mappings(self) -> None:
        store = MemoryStore()
        rev = get_json(store)["mappingConfig"]["revision"]
        post_form(store, {"action": "preset", "revision": rev, "preset": "pro-1yuan"})

        flow = make_flow(resp_body=json.dumps(["g1.ios.2tb.m.3month_ip_75p"]))
        g1_acq_mitm.process_response(flow, store)
        self.assertEqual(len(get_json(store)["scan"]["skus"]), 1)

        # ?format=json&clear=1 must NOT clear.
        f_json_clear = make_flow(url=REPORT + "?format=json&clear=1")
        g1_acq_mitm.process_request(f_json_clear, store)
        self.assertEqual(f_json_clear.response.status_code, 200)
        self.assertEqual(len(json.loads(f_json_clear.response.get_text(strict=True))["scan"]["skus"]), 1)

        # ?clear=1 clears scan and test, redirects 303, and preserves custom mappings!
        f_clear = make_flow(url=REPORT + "?clear=1")
        g1_acq_mitm.process_request(f_clear, store)
        self.assertEqual(f_clear.response.status_code, 303)
        self.assertEqual(f_clear.response.headers["Location"], f"{REPORT}?notice=cleared")

        rep = get_json(store)
        self.assertEqual(rep["scan"]["skus"], [])
        self.assertEqual(rep["test"]["hitCount"], 0)
        self.assertEqual(rep["configuredMode"], "custom")
        self.assertEqual(rep["configuredTarget"], GEMINI_PRO_TARGET)

    def test_corrupt_config_pauses_rewriting_until_reset(self) -> None:
        store = MemoryStore({mapping_config.KEY: "{corrupt-json"})
        flow = make_flow(resp_body=json.dumps([TWENTY]))
        g1_acq_mitm.process_response(flow, store)
        self.assertEqual(json.loads(flow.response.get_text(strict=True)), [TWENTY])

        rep = get_json(store)
        self.assertEqual(rep["mappingConfig"]["status"], "invalid")
        self.assertEqual(rep["test"]["status"], "config-error")

        res = post_form(store, {"action": "reset", "revision": "invalid"})
        self.assertEqual(res.response.status_code, 303)
        self.assertEqual(get_json(store)["mappingConfig"]["status"], "default")

    def test_escaped_dots_and_local_state_file_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "g1_acq_state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"scan": {}, "test": {}}, f)

            file_store = g1_acq_mitm.LocalStateStore(state_path)
            escaped = r"g1\u002eios\u002e2tb\u002eescaped"
            flow = make_flow(resp_body=escaped)
            g1_acq_mitm.process_response(flow, file_store)
            # Escaped copy discovered, original response untouched.
            self.assertEqual(flow.response.get_text(strict=True), escaped)
            rep = get_json(file_store)
            self.assertEqual(rep["scan"]["skus"][0]["id"], "g1.ios.2tb.escaped")

            # Preset persistence round-trip through g1_acq_state.json
            rev = rep["mappingConfig"]["revision"]
            post_form(file_store, {"action": "preset", "revision": rev, "preset": "pro-1yuan"})
            rep2 = get_json(file_store)
            self.assertEqual(rep2["configuredMode"], "custom")
            self.assertEqual(rep2["configuredTarget"], GEMINI_PRO_TARGET)

            # Corrupt file directly on disk -> invalid config, recoverable by reset
            with open(state_path, "w", encoding="utf-8") as f:
                f.write("{broken")
            self.assertEqual(get_json(file_store)["mappingConfig"]["status"], "invalid")
            res = post_form(file_store, {"action": "reset", "revision": "invalid"})
            self.assertEqual(res.response.status_code, 303)
            self.assertEqual(get_json(file_store)["mappingConfig"]["status"], "default")

    def test_html_has_no_scripts_or_external_assets(self) -> None:
        store = MemoryStore()
        flow = make_flow(url=REPORT)
        g1_acq_mitm.process_request(flow, store)
        assert flow.response is not None
        self.assertEqual(flow.response.status_code, 200)
        body = flow.response.get_text(strict=True)
        self.assertIsNone(re.search(r"<(?:script|iframe|img|object|embed)\b", body, re.IGNORECASE))
        self.assertIn("v7.12.0-mitm", body)
        self.assertIn("pro-1yuan", body)
        self.assertIn("tr-ultra-20tb", body)
        self.assertIn("tr-ultra-30tb", body)
        self.assertIn("ultra-75p", body)
        self.assertIn("pro-12months-90p", body)


if __name__ == "__main__":
    unittest.main()
