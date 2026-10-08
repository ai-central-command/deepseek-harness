#!/usr/bin/env python3
"""Offline, read-only validation of captured AI Hub interface evidence."""

import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from pathlib import Path, PurePosixPath

VERSION = "2.0.0"
MANIFEST_VERSION = "validator-v2-evidence-bundle-v1"
RESULT_VERSION = "validator-v2-result-v1"
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 500
MAX_RUNTIME_SECONDS = 30
MAX_OUTPUT = 65536
ALLOWED_STATUS_OPS = ["coding", "aider", "backend", "controller", "feedback", "inspect"]
SAFE_SLUG = r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}"
EXPECTED_OPERATIONS = [
    "vps_list", "vps_find", "vps_read", "vps_git_status", "vps_git_log",
    "vps_search_read", "vps_search_content", "vps_repo_summary",
]
EXPECTED_ARGS = {
    "vps_list": {"path": (True, None)},
    "vps_find": {"root": (True, None), "name": (True, None), "max_results": (True, None)},
    "vps_read": {"path": (True, None), "start_line": (True, None), "max_lines": (True, None)},
    "vps_git_status": {"repo": (True, None)},
    "vps_git_log": {"repo": (True, None), "max_entries": (True, None)},
    "vps_search_read": {"root": (True, None), "name": (True, None), "match": (True, ["exact", "contains"]),
                         "result_index": (True, None), "start_line": (True, None), "max_lines": (True, None)},
    "vps_search_content": {"pattern": (True, None), "path": (False, None), "max_matches": (False, None),
                           "max_files": (False, None), "max_file_bytes": (False, None)},
    "vps_repo_summary": {"repo": (True, None), "max_entries": (True, None), "max_commits": (True, None)},
}
RECEIPTS = {
    "BASE_IMAGE_ADMISSION_RECEIPT": ("base-image-admission-v1", [
        "schema_version", "policy_id", "source_mode", "immutable_source_reference", "archive_object_identity",
        "archive_sha256", "platform", "oci_index_digest", "platform_manifest_digest", "image_config_digest",
        "ordered_rootfs_layer_digests", "acquired_at", "acquisition_mechanism", "verifier_identity", "verification_result"]),
    "VALIDATOR_IMAGE_BUILD_RECEIPT": ("validator-image-build-receipt-v1", [
        "schema_version", "policy_id", "build_authority_grant_sha256", "base_admission_receipt_sha256",
        "dockerfile_sha256", "build_context_manifest_sha256", "build_command", "build_engine_identity", "platform",
        "image_digest", "platform_manifest_digest", "image_config_digest", "ordered_rootfs_layer_digests",
        "python_path", "python_version", "python_binary_sha256", "builder_identity", "build_result"]),
    "VALIDATOR_IMAGE_PUBLICATION_RECEIPT": ("validator-image-publication-receipt-v1", [
        "schema_version", "policy_id", "publication_authority_grant_sha256", "image_digest", "platform",
        "platform_manifest_digest", "image_config_digest", "ordered_rootfs_layer_digests", "build_receipt_sha256",
        "dockerfile_sha256", "build_context_manifest_sha256", "acceptance_result_sha256", "primary_store_identity",
        "primary_object_identity", "archive_store_identity", "archive_object_identity", "archive_sha256",
        "publication_result", "reviewer_identity"]),
    "VALIDATOR_IMAGE_RETRIEVAL_RECEIPT": ("validator-image-retrieval-receipt-v1", [
        "schema_version", "policy_id", "publication_receipt_sha256", "requested_image_digest", "source_mode",
        "source_identity", "retrieved_object_identity", "transport_or_archive_sha256", "verified_platform",
        "verified_manifest_digest", "verified_config_digest", "verified_rootfs_layer_digests",
        "retrieval_mechanism", "verifier_identity", "verification_result"]),
}
CRITERIA = [
    "V2-FUNC-001", "V2-FUNC-002", "V2-FUNC-003", "V2-FUNC-004",
    "V2-SCHEMA-001", "V2-SCHEMA-002", "V2-SCHEMA-003", "V2-SCHEMA-004", "V2-SCHEMA-005",
    "V2-SEC-001", "V2-SEC-002", "V2-SEC-003", "V2-SEC-004", "V2-CAP-001", "V2-CAP-002",
]
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class InputError(Exception):
    """The invocation or evidence bundle is invalid or unsafe."""


class ValidationError(Exception):
    """A well-formed bundle failed a validator requirement."""


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise InputError("non_finite_json_number")


def canonical_json(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise InputError("json_not_canonicalizable")


def _load_json(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates, parse_constant=_reject_constant)
    except InputError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise InputError("malformed_json")


def _safe_relative_path(value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise InputError("invalid_relative_path")
    if "\\" in value or "\x00" in value or any(ord(ch) < 32 for ch in value):
        raise InputError("invalid_relative_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise InputError("path_escape")
    return path


def _checked_root(value):
    if not isinstance(value, str) or not value:
        raise InputError("invalid_evidence_root")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise InputError("evidence_root_unavailable")
    if candidate.absolute() != resolved or not resolved.is_dir():
        raise InputError("evidence_root_not_canonical_directory")
    return resolved


def _read_beneath(root, rel, budget):
    path = _safe_relative_path(rel)
    candidate = root
    try:
        for part in path.parts:
            candidate = candidate / part
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise InputError("symlink_rejected")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise InputError("path_not_regular_file_beneath_root")
        fd = os.open(str(candidate), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise InputError("path_not_regular_file")
            if info.st_size > MAX_FILE:
                raise InputError("file_size_limit")
            raw = bytearray()
            while len(raw) <= MAX_FILE:
                if time.monotonic() > budget[1]:
                    raise InputError("runtime_limit")
                chunk = os.read(fd, min(65536, MAX_FILE + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_FILE:
                raise InputError("file_size_limit")
        finally:
            os.close(fd)
    except InputError:
        raise
    except FileNotFoundError:
        raise InputError("referenced_file_missing")
    except OSError:
        raise InputError("referenced_file_inaccessible")
    budget[0] += len(raw)
    if budget[0] > MAX_TOTAL:
        raise InputError("aggregate_size_limit")
    if time.monotonic() > budget[1]:
        raise InputError("runtime_limit")
    return bytes(raw)


def _strict_fields(obj, fields, reason):
    if not isinstance(obj, dict) or set(obj) != set(fields):
        raise InputError(reason)


def _manifest(root, source_commit_arg):
    budget = [0, time.monotonic() + MAX_RUNTIME_SECONDS]
    raw = _read_beneath(root, "manifest.json", budget)
    data = _load_json(raw)
    required = {"schema_version", "source_commit", "files", "interface_inventory", "status_fixtures", "receipt_fixtures"}
    if not isinstance(data, dict) or set(data) != required:
        raise InputError("manifest_fields_invalid")
    if data["schema_version"] != MANIFEST_VERSION:
        raise InputError("unsupported_manifest_schema")
    source_commit = data["source_commit"]
    if source_commit is not None and (not isinstance(source_commit, str) or not COMMIT_SHA.fullmatch(source_commit)):
        raise InputError("source_commit_invalid")
    if source_commit_arg is not None and source_commit_arg != source_commit:
        raise InputError("source_commit_mismatch")
    file_list = data["files"]
    if not isinstance(file_list, list) or len(file_list) + 1 > MAX_FILES:
        raise InputError("file_count_limit")
    by_path = {}
    for entry in file_list:
        _strict_fields(entry, ("path", "sha256", "role"), "manifest_file_entry_invalid")
        rel = str(_safe_relative_path(entry["path"]))
        if rel in by_path:
            raise InputError("duplicate_manifest_path")
        if not isinstance(entry["sha256"], str) or not HEX_SHA.fullmatch(entry["sha256"]):
            raise InputError("invalid_hash_format")
        if not isinstance(entry["role"], str) or entry["role"] not in ("interface_inventory", "status_fixture", "receipt_fixture", "source_snapshot"):
            raise InputError("invalid_file_role")
        by_path[rel] = entry
    inventory_path = str(_safe_relative_path(data["interface_inventory"]))
    status_paths = data["status_fixtures"]
    receipt_entries = data["receipt_fixtures"]
    if not isinstance(status_paths, list) or not isinstance(receipt_entries, list):
        raise InputError("manifest_references_invalid")
    if not isinstance(inventory_path, str):
        raise InputError("manifest_references_invalid")
    receipt_types = set()
    refs = [(inventory_path, "interface_inventory")]
    for item in status_paths:
        refs.append((str(_safe_relative_path(item)), "status_fixture"))
    for item in receipt_entries:
        _strict_fields(item, ("path", "receipt_type"), "receipt_reference_invalid")
        receipt_type = item["receipt_type"]
        if not isinstance(receipt_type, str) or receipt_type not in RECEIPTS or receipt_type in receipt_types:
            raise InputError("receipt_type_invalid")
        receipt_types.add(receipt_type)
        refs.append((str(_safe_relative_path(item["path"])), "receipt_fixture"))
    loaded = {}
    hash_errors = []
    for rel, role in refs:
        if rel not in by_path or by_path[rel]["role"] != role:
            raise InputError("referenced_file_not_declared")
    for rel, entry in by_path.items():
        raw_file = _read_beneath(root, rel, budget)
        digest = hashlib.sha256(raw_file).hexdigest()
        if digest != entry["sha256"]:
            hash_errors.append(rel)
        loaded[rel] = (raw_file, digest, entry["role"])
    decoded = {}
    for rel, _role in refs:
        decoded[rel] = _load_json(loaded[rel][0])
    return data, source_commit, by_path, loaded, decoded, hash_errors


def _schema_fields_match(actual, expected):
    if not isinstance(actual, dict) or set(actual) != set(expected):
        return False
    for operation, fields in expected.items():
        if not isinstance(actual[operation], dict) or set(actual[operation]) != set(fields):
            return False
        for key, (required, enum) in fields.items():
            prop = actual[operation][key]
            if not isinstance(prop, dict) or prop.get("type") != "string" or prop.get("required", False) is not required:
                return False
            if enum is None and "enum" in prop:
                return False
            if enum is not None and prop.get("enum") != enum:
                return False
    return True


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _receipt_valid(receipt_type, receipt):
    version, fields = RECEIPTS[receipt_type]
    if not isinstance(receipt, dict) or receipt.get("schema_version") != version:
        raise InputError("unsupported_receipt_schema")
    if not set(fields).issubset(receipt):
        return False
    if "receipt_sha256" in receipt:
        return False
    if receipt_type == "BASE_IMAGE_ADMISSION_RECEIPT":
        if receipt.get("source_mode") not in ("oci_registry", "authenticated_oci_archive"):
            return False
        if receipt.get("verification_result") not in ("PASS", "FAIL"):
            return False
        if not isinstance(receipt.get("ordered_rootfs_layer_digests"), list):
            return False
        for name in ("image_config_digest", "platform_manifest_digest"):
            if not _digest(receipt.get(name)):
                return False
        if not all(_digest(x) for x in receipt["ordered_rootfs_layer_digests"]):
            return False
    else:
        for name, value in receipt.items():
            if name.endswith("sha256") and value is not None and not HEX_SHA.fullmatch(value if isinstance(value, str) else ""):
                return False
        for name in ("image_digest", "platform_manifest_digest", "image_config_digest", "requested_image_digest", "verified_manifest_digest", "verified_config_digest"):
            if name in receipt and not _digest(receipt[name]):
                return False
        for name in ("ordered_rootfs_layer_digests", "verified_rootfs_layer_digests"):
            if name in receipt and (not isinstance(receipt[name], list) or not all(_digest(x) for x in receipt[name])):
                return False
    try:
        canonical_json(receipt)
    except InputError:
        return False
    return True


def _status_valid(value):
    fields = {"read_only", "operation", "project", "observed_at", "result"}
    if not isinstance(value, dict) or set(value) != fields:
        return False
    if value["read_only"] is not True or value["operation"] not in ALLOWED_STATUS_OPS:
        return False
    if not isinstance(value["project"], str) or not re.fullmatch(SAFE_SLUG, value["project"]):
        return False
    timestamp = value["observed_at"]
    if not isinstance(timestamp, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", timestamp):
        return False
    return isinstance(value["result"], dict)


def _self_boundary_valid():
    try:
        import ast
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    except Exception:
        return False
    forbidden_modules = {"subprocess", "socket", "urllib", "http", "requests", "boto3", "docker", "paramiko", "ftplib"}
    forbidden_calls = {"exec", "eval", "system", "popen", "Popen", "run", "call", "check_call", "check_output"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[0] in forbidden_modules for alias in node.names):
            return False
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in forbidden_modules:
            return False
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name in forbidden_calls:
                return False
    return True


def _make_checks(inv, statuses, receipts, paths_safe, hash_errors):
    ids = CRITERIA
    checks = {key: {"id": key, "status": "PASS", "reason": "requirement_satisfied", "evidence": []} for key in ids}
    def fail(key, reason):
        checks[key]["status"] = "FAIL"
        checks[key]["reason"] = reason
    operations = inv.get("tool_names") if isinstance(inv, dict) else None
    schemas = inv.get("schemas") if isinstance(inv, dict) else None
    if not isinstance(inv, dict) or inv.get("schema_version") != "managed-vps-tool-interface-v1" or inv.get("package") != "@deepseek-ai/dsh-tool-vps-readonly":
        fail("V2-FUNC-001", "interface_inventory_schema_mismatch")
    elif not _schema_fields_match(schemas, EXPECTED_ARGS):
        fail("V2-FUNC-001", "tool_argument_schema_mismatch")
    if operations != EXPECTED_OPERATIONS:
        fail("V2-CAP-001", "required_read_only_operation_set_mismatch")
    wrapper = inv.get("status_cli", {}) if isinstance(inv, dict) else {}
    if (not isinstance(wrapper, dict) or wrapper.get("operations") != ALLOWED_STATUS_OPS
            or wrapper.get("project_slug_pattern") != SAFE_SLUG or wrapper.get("fixed_remote") is not True):
        fail("V2-FUNC-002", "status_wrapper_contract_mismatch")
    if not statuses or any(not _status_valid(item) for item in statuses):
        fail("V2-FUNC-003", "status_envelope_invalid")
    limits = inv.get("content_search_limits", {}) if isinstance(inv, dict) else {}
    expected_limits = {"root": "/srv/ai-hub", "literal_ascii": True, "max_matches": 200,
                       "max_files": 10000, "max_file_bytes": 8388608, "max_line_bytes": 1024, "timeout_seconds": 20}
    if (not isinstance(inv, dict) or inv.get("approved_root") != "/srv/ai-hub"
            or limits != expected_limits or not _schema_fields_match(schemas, EXPECTED_ARGS)):
        fail("V2-FUNC-004", "bounded_path_or_content_search_contract_mismatch")
    receipt_status = {}
    for receipt_type, value in receipts.items():
        receipt_status[receipt_type] = _receipt_valid(receipt_type, value)
    for key, receipt_type in zip(("V2-SCHEMA-001", "V2-SCHEMA-002", "V2-SCHEMA-003", "V2-SCHEMA-004"), RECEIPTS):
        if not receipt_status.get(receipt_type, False):
            fail(key, "receipt_schema_invalid")
    canonical_values = [canonical_json(value) for value in receipts.values()]
    if any("receipt_sha256" in value for value in receipts.values()):
        fail("V2-SCHEMA-005", "receipt_hash_must_be_external")
    if not paths_safe:
        fail("V2-SEC-001", "evidence_path_confinement_failed")
    mutation_names = {"put", "delete", "write", "execute", "deploy", "create_candidate", "resume_lifecycle", "publish"}
    if not _self_boundary_valid() or not isinstance(operations, list) or any(any(part in op.lower() for part in mutation_names) for op in operations if isinstance(op, str)):
        fail("V2-SEC-002", "mutation_or_external_command_surface_detected")
        fail("V2-CAP-002", "controller_mutation_capability_detected")
    if hash_errors:
        fail("V2-SEC-004", "evidence_hash_mismatch")
    # Output contains only fixed reason codes and path/hash references, never input values.
    return [checks[key] for key in sorted(checks)]


def _result(source_commit, checks, evidence):
    failures = [item["id"] for item in checks if item["status"] != "PASS"]
    return {"schema_version": RESULT_VERSION, "validator_version": VERSION,
            "source_commit": source_commit, "status": "FAIL" if failures else "PASS",
            "checks": checks, "failures": failures, "evidence": evidence}


def validate_bundle(root_arg, source_commit_arg=None):
    root = _checked_root(root_arg)
    manifest, source_commit, entries, loaded, decoded, hash_errors = _manifest(root, source_commit_arg)
    inventory_path = str(_safe_relative_path(manifest["interface_inventory"]))
    status_paths = [str(_safe_relative_path(path)) for path in manifest["status_fixtures"]]
    receipt_paths = {item["receipt_type"]: str(_safe_relative_path(item["path"])) for item in manifest["receipt_fixtures"]}
    inventory = decoded[inventory_path]
    statuses = [decoded[path] for path in status_paths]
    receipts = {kind: decoded[path] for kind, path in receipt_paths.items()}
    checks = _make_checks(inventory, statuses, receipts, True, hash_errors)
    evidence_paths = sorted(set([inventory_path] + status_paths + list(receipt_paths.values())))
    evidence = [{"path": path, "sha256": loaded[path][1], "role": loaded[path][2]} for path in evidence_paths]
    return _result(source_commit, checks, evidence)


def _error_result(kind):
    check_id = "V2-INPUT" if kind == "input_error" else "V2-INTERNAL"
    check = {"id": check_id, "status": "FAIL", "reason": kind, "evidence": []}
    return _result(None, [check], [])


def parse_args(argv):
    allowed = {"--evidence-root", "--source-commit"}
    if len(argv) not in (2, 4):
        raise InputError("invocation_invalid")
    pairs = {}
    for offset in range(0, len(argv), 2):
        key, value = argv[offset:offset + 2]
        if key not in allowed or key in pairs or not value:
            raise InputError("invocation_invalid")
        pairs[key] = value
    if "--evidence-root" not in pairs or set(pairs) - allowed:
        raise InputError("invocation_invalid")
    commit = pairs.get("--source-commit")
    if commit is not None and not COMMIT_SHA.fullmatch(commit):
        raise InputError("source_commit_invalid")
    return pairs["--evidence-root"], commit


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        root, commit = parse_args(argv)
        result = validate_bundle(root, commit)
        exit_code = 1 if result["status"] == "FAIL" else 0
    except InputError:
        result = _error_result("input_error")
        exit_code = 2
    except Exception:
        result = _error_result("internal_error")
        exit_code = 3
    output = canonical_json(result) + b"\n"
    if len(output) > MAX_OUTPUT:
        output = canonical_json(_error_result("input_error")) + b"\n"
        exit_code = 2
    sys.stdout.buffer.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
