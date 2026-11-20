#!/usr/bin/env python3
"""Fail closed for newly changed, unsafe GitHub Actions workflows.

Pre-existing workflow risks are inventoried, not silently reclassified as safe.
No third-party Python packages are required.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

WORKFLOWS = Path(".github/workflows")
OUT = Path("security-evidence/workflow-trust.json")
PIN = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)


def problems(content):
    issues = []
    if not re.search(r"^permissions:\s*(?:\{[^\n]*\})?\s*$", content, re.MULTILINE):
        issues.append("no explicit top-level permissions block")
    if re.search(r"^permissions:\s*write-all\b", content, re.MULTILINE):
        issues.append("workflow grants write-all permissions")
    if re.search(r"^\s*pull_request_target\s*:", content, re.MULTILINE):
        issues.append("privileged pull_request_target trigger requires separate threat review")
    refs = USES.findall(content)
    for ref in refs:
        if ref.startswith("./"):
            continue
        if ref.startswith("docker://"):
            if "@sha256:" not in ref:
                issues.append("unpinned container action: " + ref)
            continue
        commit = ref.rsplit("@", 1)[-1] if "@" in ref else ""
        if not PIN.fullmatch(commit):
            issues.append("action is not pinned to full 40-character SHA: " + ref)
    if any("actions/checkout@" in ref for ref in refs):
        if not re.search(r"^\s*persist-credentials:\s*false\s*(?:#.*)?$", content, re.MULTILINE):
            issues.append("checkout does not disable persisted credentials")
    return issues


def self_test():
    safe = ("name: test\non: pull_request\npermissions:\n  contents: read\n"
            "jobs:\n  check:\n    steps:\n"
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            "        with:\n          persist-credentials: false\n")
    assert problems(safe) == [], problems(safe)
    assert any("not pinned" in e for e in problems(safe.replace(
        "11d5960a326750d5838078e36cf38b85af677262", "v4")))
    assert any("permissions" in e for e in problems(
        safe.replace("permissions:\n  contents: read\n", "")))
    assert any("pull_request_target" in e for e in problems(
        safe.replace("on: pull_request", "on:\n  pull_request_target:")))
    assert any("persisted" in e for e in problems(
        safe.replace("persist-credentials: false", "persist-credentials: true")))
    print("Workflow policy self-tests passed")


def get_changed_paths():
    event = os.getenv("GITHUB_EVENT_NAME", "")
    base = (os.getenv("GITHUB_BASE_SHA", "") if event == "pull_request"
            else os.getenv("GITHUB_BEFORE_SHA", "") if event == "push" else "")
    if not PIN.fullmatch(base) or base == "0" * 40:
        if event in ("pull_request", "push"):
            raise RuntimeError("Cannot verify changed workflows without valid base SHA")
        return {" .github/workflows/research-security-gates.yml".strip()}
    result = subprocess.run(
        ["git", "diff", "--name-only", base, "HEAD", "--", ".github/workflows"],
        check=True, capture_output=True, text=True)
    return set(result.stdout.splitlines())


def main():
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    changes = get_changed_paths()
    inventory = {}
    violations = {}
    for path in files:
        rel = path.as_posix()
        findings = problems(path.read_text(encoding="utf-8"))
        inventory[rel] = findings
        if rel in changes and findings:
            violations[rel] = findings
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "policy": "changed workflows fail closed; legacy risks inventory only",
        "event": os.getenv("GITHUB_EVENT_NAME", "local"),
        "changed_workflows": sorted(changes),
        "inventory": inventory,
        "violations": violations,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Inventoried {len(files)} workflows; {sum(bool(x) for x in inventory.values())} "
          f"with findings; {len(violations)} changed workflows violating policy")
    for path, findings in violations.items():
        print(path + ": " + "; ".join(findings), file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        try:
            sys.exit(main())
        except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
            print(f"Cannot determine security policy: {exc}", file=sys.stderr)
            sys.exit(2)
