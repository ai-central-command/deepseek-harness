#!/usr/bin/env python3
"""Source-level acceptance tests for the offline validator-v2 contract."""
import argparse
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path("/fixtures") if Path("/fixtures").is_dir() else ROOT / "fixtures"
EXPECTED_CRITERIA = [
    "V2-FUNC-001", "V2-FUNC-002", "V2-FUNC-003", "V2-FUNC-004",
    "V2-SCHEMA-001", "V2-SCHEMA-002", "V2-SCHEMA-003", "V2-SCHEMA-004", "V2-SCHEMA-005",
    "V2-SEC-001", "V2-SEC-002", "V2-SEC-003", "V2-SEC-004", "V2-CAP-001", "V2-CAP-002",
]
EXPECTED_FIXTURES = [
    "known-good/manifest.json", "known-good/interfaces/managed-tool-schema.json",
    "known-good/status/controller-status.json", "known-good/receipts/base-image-admission.json",
    "known-good/receipts/validator-image-build.json", "known-good/receipts/validator-image-publication.json",
    "known-good/receipts/validator-image-retrieval.json", "known-bad/validation-fail/manifest.json",
    "known-bad/validation-fail/interfaces/managed-tool-schema.json", "negative/malformed-json/manifest.json",
    "negative/unsupported-manifest-version/manifest.json", "negative/unsupported-receipt-version/receipt.json",
    "negative/missing-required-field/status.json", "negative/path-traversal/manifest.json",
    "negative/out-of-root/manifest.json", "negative/unknown-field/manifest.json",
    "negative/mutation-attempt/interfaces/managed-tool-schema.json", "negative/missing-path/manifest.json",
    "negative/credential-sentinel/status.json", "negative/resource-limit/manifest.json",
    "negative/malformed-receipt/receipt.json", "negative/invalid-hash/manifest.json",
    "negative/output-limit/manifest.json", "negative/unsupported-operation/status.json",
]
spec = importlib.util.spec_from_file_location("validator_v2", ROOT / "validator.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
SOURCE_COMMIT = "6530ebf487150c72ef5033ebe32f4e1849e6ddeb"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def invoke(root, *extra):
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-I", str(ROOT / "validator.py"), "--evidence-root", str(root), "--source-commit", SOURCE_COMMIT, *extra],
        capture_output=True, env=env, timeout=5, check=False,
    )


def working_bundle(transform=None):
    temp = tempfile.TemporaryDirectory(dir="/private/tmp")
    root = Path(temp.name) / "evidence"
    shutil.copytree(FIXTURES / "known-good", root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if transform:
        transform(root, manifest)
    # Recompute declared hashes for the fixture's referenced files.
    for entry in manifest["files"]:
        file_path = root / entry["path"]
        try:
            exists = file_path.is_file()
        except OSError:
            exists = False
        if exists and isinstance(entry.get("sha256"), str) and len(entry["sha256"]) == 64:
            entry["sha256"] = hashlib.sha256(file_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(canonical(manifest))
    return temp, root


def check_map(root):
    result = validator.validate_bundle(str(root), SOURCE_COMMIT)
    return {item["id"]: item for item in result["checks"]}


class ValidatorContractTests(unittest.TestCase):
    def test_v2_func_001_exact_tool_schemas(self):
        temp, root = working_bundle()
        with temp:
            self.assertEqual(check_map(root)["V2-FUNC-001"]["status"], "PASS")
            def change(_root, manifest):
                interface = json.loads((_root / manifest["interface_inventory"]).read_text())
                interface["tool_names"].remove("vps_search_content")
                interface["schemas"].pop("vps_search_content")
                (_root / manifest["interface_inventory"]).write_bytes(canonical(interface))
            temp2, root2 = working_bundle(change)
            with temp2:
                self.assertEqual(check_map(root2)["V2-FUNC-001"]["status"], "FAIL")

    def test_v2_func_002_fixed_status_wrapper_and_slug(self):
        temp, root = working_bundle()
        with temp:
            def change(_root, manifest):
                p = _root / manifest["interface_inventory"]
                data = json.loads(p.read_text()); data["status_cli"]["fixed_remote"] = False; p.write_bytes(canonical(data))
            temp2, root2 = working_bundle(change)
            with temp2: self.assertEqual(check_map(root2)["V2-FUNC-002"]["status"], "FAIL")
            self.assertRegex("synthetic-fixture", validator.SAFE_SLUG)
            self.assertIsNone(__import__("re").fullmatch(validator.SAFE_SLUG, "../bad"))

    def test_v2_func_003_status_envelope(self):
        def change(root, manifest):
            p = root / manifest["status_fixtures"][0]
            data = json.loads(p.read_text()); data.pop("read_only"); p.write_bytes(canonical(data))
        temp, root = working_bundle(change)
        with temp: self.assertEqual(check_map(root)["V2-FUNC-003"]["status"], "FAIL")

    def test_v2_func_004_root_and_bounds(self):
        def change(root, manifest):
            p = root / manifest["interface_inventory"]
            data = json.loads(p.read_text()); data["content_search_limits"]["max_files"] = 10001; p.write_bytes(canonical(data))
        temp, root = working_bundle(change)
        with temp: self.assertEqual(check_map(root)["V2-FUNC-004"]["status"], "FAIL")

    def _receipt_missing_field(self, receipt_type, criterion):
        def change(root, manifest):
            entry = next(x for x in manifest["receipt_fixtures"] if x["receipt_type"] == receipt_type)
            p = root / entry["path"]; data = json.loads(p.read_text()); data.pop(next(k for k in data if k != "schema_version")); p.write_bytes(canonical(data))
        temp, root = working_bundle(change)
        with temp:
            self.assertEqual(check_map(root)[criterion]["status"], "FAIL")

    def test_v2_schema_001_admission_receipt(self): self._receipt_missing_field("BASE_IMAGE_ADMISSION_RECEIPT", "V2-SCHEMA-001")
    def test_v2_schema_002_build_receipt(self): self._receipt_missing_field("VALIDATOR_IMAGE_BUILD_RECEIPT", "V2-SCHEMA-002")
    def test_v2_schema_003_publication_receipt(self): self._receipt_missing_field("VALIDATOR_IMAGE_PUBLICATION_RECEIPT", "V2-SCHEMA-003")
    def test_v2_schema_004_retrieval_receipt(self): self._receipt_missing_field("VALIDATOR_IMAGE_RETRIEVAL_RECEIPT", "V2-SCHEMA-004")

    def test_v2_schema_005_canonical_json_and_external_hash(self):
        value = {"z": 1, "a": 2}
        self.assertEqual(validator.canonical_json(value), validator.canonical_json({"a": 2, "z": 1}))
        with self.assertRaises(validator.InputError): validator.canonical_json({"number": float("nan")})
        def change(root, manifest):
            entry = manifest["receipt_fixtures"][0]; p=root / entry["path"]; data=json.loads(p.read_text()); data["receipt_sha256"]="a"*64; p.write_bytes(canonical(data))
        temp, root = working_bundle(change)
        with temp: self.assertEqual(check_map(root)["V2-SCHEMA-001"]["status"], "FAIL")

    def test_v2_sec_001_traversal_absolute_and_symlink_escape(self):
        for path in ("../outside.json", "/etc/passwd"):
            with self.assertRaises(validator.InputError): validator._safe_relative_path(path) if not path.startswith("/") else validator._safe_relative_path(path)
        temp, root = working_bundle()
        with temp:
            outside = Path(temp.name) / "outside.json"; outside.write_text("{}")
            (root / "escape.json").symlink_to(outside)
            with self.assertRaises(validator.InputError): validator._read_beneath(root, "escape.json", [0])

    def test_v2_sec_002_no_mutation_or_external_execution(self):
        self.assertTrue(validator._self_boundary_valid())
        def change(root, manifest):
            p=root/manifest["interface_inventory"]; data=json.loads(p.read_text()); data["tool_names"].append("vps_delete"); data["schemas"]["vps_delete"]={}; p.write_bytes(canonical(data))
        temp, root = working_bundle(change)
        with temp:
            checks=check_map(root); self.assertEqual(checks["V2-CAP-001"]["status"], "FAIL"); self.assertEqual(checks["V2-SEC-002"]["status"], "FAIL")

    def test_v2_sec_003_sentinel_not_emitted(self):
        def change(root, manifest):
            p=root/manifest["status_fixtures"][0]; data=json.loads(p.read_text()); data["result"]["token"]="SENTINEL-SECRET"; p.write_bytes(canonical(data))
        temp, root = working_bundle(change)
        with temp:
            proc=invoke(root); self.assertNotIn(b"SENTINEL-SECRET", proc.stdout); self.assertNotIn(b"SENTINEL-SECRET", proc.stderr)

    def test_v2_sec_004_fail_closed_and_resource_bounds(self):
        fixture=FIXTURES/"negative/malformed-json/manifest.json"
        self.assertEqual(json.loads(fixture.read_text()) if False else fixture.read_bytes(), b"{malformed")
        for value in ("x"*513, "../bad", "/etc/passwd"):
            with self.assertRaises(validator.InputError): validator._safe_relative_path(value)
        with self.assertRaises(validator.InputError): validator.parse_args(["--evidence-root", "/tmp", "--unknown", "x"])
        with self.assertRaises(validator.InputError): validator._load_json(b'{"x":NaN}')

    def test_all_negative_fixture_files_exercise_contract(self):
        def set_manifest(**values):
            def change(_root, manifest):
                manifest.update(values)
            return change
        def replace_status(fixture):
            def change(root, manifest):
                shutil.copyfile(fixture, root / manifest["status_fixtures"][0])
            return change
        def replace_interface(fixture):
            def change(root, manifest):
                shutil.copyfile(fixture, root / manifest["interface_inventory"])
            return change
        def replace_receipt(fixture):
            def change(root, manifest):
                shutil.copyfile(fixture, root / manifest["receipt_fixtures"][0]["path"])
            return change
        cases = {
            "unsupported-manifest-version/manifest.json": (set_manifest(schema_version="validator-v2-evidence-bundle-v0"), 2),
            "unsupported-receipt-version/receipt.json": (replace_receipt(FIXTURES/"negative/unsupported-receipt-version/receipt.json"), 2),
            "missing-required-field/status.json": (replace_status(FIXTURES/"negative/missing-required-field/status.json"), 1),
            "path-traversal/manifest.json": (set_manifest(interface_inventory="../outside.json"), 2),
            "out-of-root/manifest.json": (set_manifest(interface_inventory="/etc/passwd"), 2),
            "unknown-field/manifest.json": (set_manifest(unauthorized_field=True), 2),
            "mutation-attempt/interfaces/managed-tool-schema.json": (replace_interface(FIXTURES/"negative/mutation-attempt/interfaces/managed-tool-schema.json"), 1),
            "missing-path/manifest.json": (set_manifest(interface_inventory="interfaces/not-present.json"), 2),
            "credential-sentinel/status.json": (replace_status(FIXTURES/"negative/credential-sentinel/status.json"), 0),
            "resource-limit/manifest.json": (set_manifest(files=[{"path":"x"*513,"sha256":"a"*64,"role":"source_snapshot"}]), 2),
            "malformed-receipt/receipt.json": (replace_receipt(FIXTURES/"negative/malformed-receipt/receipt.json"), 1),
            "invalid-hash/manifest.json": (set_manifest(files=[{"path":"interfaces/managed-tool-schema.json","sha256":"invalid","role":"interface_inventory"}]), 2),
            "unsupported-operation/status.json": (replace_status(FIXTURES/"negative/unsupported-operation/status.json"), 1),
        }
        for rel, (transform, expected_exit) in cases.items():
            with self.subTest(fixture=rel):
                temp, root = working_bundle(transform)
                with temp:
                    proc = invoke(root)
                    self.assertEqual(proc.returncode, expected_exit, proc.stdout.decode())
                    if "credential-sentinel" in rel:
                        self.assertNotIn(b"SENTINEL-CREDENTIAL-DO-NOT-OUTPUT", proc.stdout)
        malformed = FIXTURES/"negative/malformed-json/manifest.json"
        self.assertEqual(malformed.read_bytes(), b"{malformed")

    def test_output_is_bounded_at_contract_limit(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name) / "evidence"; (root / "interfaces").mkdir(parents=True); (root / "status").mkdir()
            interface = json.loads((FIXTURES/"known-good/interfaces/managed-tool-schema.json").read_text())
            (root/"interfaces/schema.json").write_bytes(canonical(interface))
            file_entries=[{"path":"interfaces/schema.json","sha256":hashlib.sha256((root/"interfaces/schema.json").read_bytes()).hexdigest(),"role":"interface_inventory"}]
            status_paths=[]
            for index in range(498):
                rel=f"status/{index:03d}-"+"x"*90+".json"
                path=root/rel;path.write_bytes(canonical({"read_only":True,"operation":"controller","project":"fixture","observed_at":"2026-01-01T00:00:00Z","result":{}}))
                file_entries.append({"path":rel,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"role":"status_fixture"});status_paths.append(rel)
            (root/"manifest.json").write_bytes(canonical({"schema_version":"validator-v2-evidence-bundle-v1","source_commit":SOURCE_COMMIT,"files":file_entries,"interface_inventory":"interfaces/schema.json","status_fixtures":status_paths,"receipt_fixtures":[]}))
            proc=invoke(root)
            self.assertLessEqual(len(proc.stdout),validator.MAX_OUTPUT)
            self.assertEqual(proc.returncode,2)

    def test_v2_cap_001_required_operations_detected(self):
        good=check_map(FIXTURES/"known-good")
        self.assertEqual(good["V2-CAP-001"]["status"], "PASS")
        manifest=json.loads((FIXTURES/"known-bad/validation-fail/manifest.json").read_text())
        self.assertNotIn("vps_search_content", json.loads((FIXTURES/"known-bad/validation-fail"/manifest["interface_inventory"]).read_text())["tool_names"])

    def test_v2_cap_002_offline_no_controller_authority(self):
        source=(ROOT/"validator.py").read_text()
        for denied in ("subprocess", "socket", "urllib", "paramiko", "docker"):
            self.assertNotIn("import "+denied, source)
        self.assertTrue(validator._self_boundary_valid())

    def test_exit_codes_and_known_fixtures(self):
        good=invoke(FIXTURES/"known-good")
        self.assertEqual(good.returncode, 0, good.stdout.decode())
        self.assertEqual(json.loads(good.stdout)["status"], "PASS")
        # The contract's bad manifest is nested; mirror it to its declared runtime mount root.
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root=Path(temp_name)/"known-bad"; shutil.copytree(FIXTURES/"known-bad/validation-fail", root)
            bad=invoke(root)
        self.assertEqual(bad.returncode, 1, bad.stdout.decode())
        self.assertEqual(json.loads(bad.stdout)["status"], "FAIL")
        input_error=invoke("/path/that/does/not/exist")
        self.assertEqual(input_error.returncode, 2)
        saved = validator.validate_bundle
        class BufferOutput:
            def __init__(self): self.buffer = io.BytesIO()
        output = BufferOutput()
        try:
            validator.validate_bundle = lambda *_args: (_ for _ in ()).throw(RuntimeError("private detail"))
            old_stdout = sys.stdout; sys.stdout = output
            self.assertEqual(validator.main(["--evidence-root", str(FIXTURES/"known-good")]), 3)
        finally:
            sys.stdout = old_stdout; validator.validate_bundle = saved
        record=json.loads(output.buffer.getvalue())
        self.assertEqual(record["checks"][0]["id"],"V2-INTERNAL")
        self.assertNotIn(b"private detail",output.buffer.getvalue())

    def test_deterministic_output_and_no_writes(self):
        before={p.relative_to(FIXTURES).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in FIXTURES.rglob("*") if p.is_file()}
        a=invoke(FIXTURES/"known-good"); b=invoke(FIXTURES/"known-good")
        self.assertEqual(a.stdout,b.stdout)
        after={p.relative_to(FIXTURES).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in FIXTURES.rglob("*") if p.is_file()}
        self.assertEqual(before,after)

    def test_fixture_inventory_matches_contract(self):
        actual={p.relative_to(FIXTURES).as_posix() for p in FIXTURES.rglob("*") if p.is_file()}
        self.assertEqual(actual,set(EXPECTED_FIXTURES))

    def test_imports_are_stdlib_only_and_contract_bindings(self):
        tree=__import__("ast").parse((ROOT/"validator.py").read_text())
        allowed={"hashlib","json","math","os","re","stat","sys","pathlib","ast","time"}
        imports=set()
        for n in __import__("ast").walk(tree):
            if isinstance(n,__import__("ast").Import): imports.update(a.name.split('.')[0] for a in n.names)
            elif isinstance(n,__import__("ast").ImportFrom) and n.module: imports.add(n.module.split('.')[0])
        self.assertTrue(imports <= allowed, imports-allowed)
        self.assertEqual(validator.CRITERIA,EXPECTED_CRITERIA)


def suite_for(name):
    loader=unittest.TestLoader()
    suite=loader.loadTestsFromTestCase(ValidatorContractTests)
    if name=="full": return suite
    selected={"test_v2_func_001_exact_tool_schemas","test_v2_func_003_status_envelope","test_exit_codes_and_known_fixtures","test_deterministic_output_and_no_writes","test_imports_are_stdlib_only_and_contract_bindings"}
    return unittest.TestSuite(ValidatorContractTests(method) for method in sorted(selected))


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--suite",choices=("fast","full"),required=True);args=parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(suite_for(args.suite))
    return 0 if result.wasSuccessful() else 1

if __name__=="__main__": raise SystemExit(main())
