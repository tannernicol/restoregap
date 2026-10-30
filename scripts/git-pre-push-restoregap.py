#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Restore Gap contributors
"""Fail-closed RestoreGap adapter for Git's pre-push hook protocol."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ZERO_OID = re.compile(r"^0+$")
HEX_OID = re.compile(r"^[0-9a-fA-F]+$")
SAFE_DIFF_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
SCRUB_GIT_ENV = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_PREFIX",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
}


class GateError(RuntimeError):
    pass


def git_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in SCRUB_GIT_ENV:
        env.pop(key, None)
    return env


def run_git(repo: Path, args: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            cwd=repo,
            env=git_env(),
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"cannot run git: {exc.strerror or type(exc).__name__}") from None
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        suffix = f": {detail[0]}" if detail else ""
        raise GateError(f"git could not resolve the repository input{suffix}")
    return result.stdout


def run_preflight(
    restoregap: str,
    repo: Path,
    *,
    diff: bytes | None = None,
    intent: dict[str, object] | None = None,
) -> None:
    if (diff is None) == (intent is None):
        raise GateError("internal adapter error: expected exactly one preflight input")
    args = [
        restoregap,
        "preflight",
        "--format",
        "json",
        "--require-coverage",
        "--fail-on-warn",
        "--diff-root",
        str(repo),
        "--actor",
        "git/pre-push",
        "--context-window",
        "git-pre-push",
    ]
    if diff is not None:
        args.extend(["--diff", "-"])
        payload = diff
    else:
        args.extend(["--intent", "-"])
        payload = (json.dumps(intent, ensure_ascii=True) + "\n").encode()
    try:
        result = subprocess.run(
            args,
            cwd=repo,
            env=git_env(),
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"cannot run RestoreGap preflight: {exc.strerror or type(exc).__name__}") from None
    if result.stdout:
        sys.stdout.buffer.write(result.stdout)
        if not result.stdout.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    if result.returncode != 0:
        raise GateError(f"RestoreGap blocked or could not evaluate the ref update (exit {result.returncode})")


def discover_repo() -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"cannot run git: {exc.strerror or type(exc).__name__}") from None
    if result.returncode != 0:
        raise GateError("cannot identify the working repository from Git's hook environment")
    try:
        return Path(os.fsdecode(result.stdout.rstrip(b"\r\n"))).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GateError(f"cannot resolve the working repository: {exc}") from None


def object_format(repo: Path) -> tuple[int, bytes]:
    value = run_git(repo, ["rev-parse", "--show-object-format"]).decode("ascii", "strict").strip()
    lengths = {"sha1": 40, "sha256": 64}
    if value not in lengths:
        raise GateError("unsupported Git object format")
    empty = run_git(repo, ["hash-object", "-t", "tree", "--stdin"], input_data=b"").strip()
    if len(empty) != lengths[value] or not HEX_OID.fullmatch(empty.decode("ascii", "strict")):
        raise GateError("Git returned an invalid empty-tree object ID")
    return lengths[value], empty


def validate_policy_location(repo: Path) -> None:
    configured = os.environ.get("RESTOREGAP_CONTEXT", "")
    if not configured:
        raise GateError("RESTOREGAP_CONTEXT must name trusted policy files outside the pushed repository")
    configured_paths = [("RESTOREGAP_CONTEXT", value) for value in configured.split(os.pathsep)]
    policy_dirs = os.environ.get("RESTOREGAP_POLICY_DIRS", "")
    if policy_dirs:
        configured_paths.extend(("RESTOREGAP_POLICY_DIRS", value) for value in policy_dirs.split(os.pathsep))
    for variable, value in configured_paths:
        if not value:
            raise GateError(f"{variable} contains an empty path")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = repo / candidate
        lexical = Path(os.path.abspath(candidate))
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            raise GateError(f"{variable} names a missing or unreadable policy path") from None
        for path in (lexical, resolved):
            try:
                path.relative_to(repo)
            except ValueError:
                continue
            raise GateError(f"{variable} must be outside the pushed repository")
        if variable == "RESTOREGAP_CONTEXT" and not resolved.is_file():
            raise GateError("RESTOREGAP_CONTEXT entries must name readable policy files")
        if variable == "RESTOREGAP_POLICY_DIRS" and not resolved.is_dir():
            raise GateError("RESTOREGAP_POLICY_DIRS entries must name readable policy directories")


def validate_ref(
    repo: Path,
    ref: str,
    *,
    local: bool = False,
    deleting: bool = False,
    local_oid: str = "",
) -> None:
    if local and ref == "HEAD":
        return
    if local and deleting and ref == "(delete)":
        return
    if local and HEX_OID.fullmatch(ref):
        if ref.lower() == local_oid.lower() and not ZERO_OID.fullmatch(ref):
            return
        raise GateError("malformed ref update input")
    if not ref.startswith("refs/") or "\x00" in ref:
        raise GateError("malformed ref update input")
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "check-ref-format", ref],
            cwd=repo,
            env=git_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"cannot validate ref name: {exc.strerror or type(exc).__name__}") from None
    if result.returncode != 0:
        raise GateError("malformed ref update input")
    if not local and not (ref.startswith("refs/heads/") or ref.startswith("refs/tags/")):
        raise GateError("unsupported remote ref namespace; only branches and tags are evaluated")


def validate_oid(value: str, oid_length: int) -> bool:
    if len(value) != oid_length or not HEX_OID.fullmatch(value):
        raise GateError("malformed ref update object ID")
    return bool(ZERO_OID.fullmatch(value))


def resolve_tree(repo: Path, oid: str, *, branch: bool) -> bytes:
    suffix = "^{commit}" if branch else "^{tree}"
    peeled = run_git(repo, ["rev-parse", "--verify", f"{oid}{suffix}"]).strip()
    if len(peeled) not in (40, 64) or not HEX_OID.fullmatch(peeled.decode("ascii", "strict")):
        raise GateError("Git returned an invalid peeled object ID")
    if branch:
        peeled_tree = run_git(repo, ["rev-parse", "--verify", f"{oid}^{{tree}}"]).strip()
        return peeled_tree
    return peeled


def is_non_fast_forward(repo: Path, old_oid: str, new_oid: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", old_oid, new_oid],
            cwd=repo,
            env=git_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"cannot inspect ref ancestry: {exc.strerror or type(exc).__name__}") from None
    if result.returncode not in (0, 1):
        raise GateError("Git could not inspect ref ancestry")
    return result.returncode == 1


def ref_kind(local_oid: str, remote_oid: str, remote_ref: str, repo: Path) -> str:
    if ZERO_OID.fullmatch(local_oid):
        return "delete"
    if ZERO_OID.fullmatch(remote_oid):
        return "create"
    if remote_ref.startswith("refs/tags/") and local_oid != remote_oid:
        return "rewrite"
    if remote_ref.startswith("refs/heads/") and is_non_fast_forward(repo, remote_oid, local_oid):
        return "rewrite"
    return "update"


def changed_path_groups(repo: Path, old_tree: bytes, new_tree: bytes) -> tuple[dict[str, list[str]], list[str]]:
    raw = run_git(
        repo,
        [
            "diff",
            "--name-status",
            "-z",
            "--no-color",
            "--no-relative",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "--no-renames",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            old_tree.decode("ascii"),
            new_tree.decode("ascii"),
            "--",
        ],
    )
    fields = raw.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2 != 0:
        raise GateError("Git returned malformed NUL-delimited changed paths")
    groups = {"modify_file": [], "delete_file": []}
    content_paths: list[str] = []
    for index in range(0, len(fields), 2):
        status, raw_path = fields[index], fields[index + 1]
        try:
            relative = raw_path.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise GateError("Git changed a path that is not valid UTF-8") from None
        path = Path(relative)
        if not relative or path.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
            raise GateError("Git returned a changed path outside the repository")
        absolute = str(repo / path)
        if status == b"D":
            groups["delete_file"].append(absolute)
        elif status in (b"A", b"M", b"T"):
            groups["modify_file"].append(absolute)
        else:
            raise GateError("Git returned an unsupported changed-path status")
        if status in (b"A", b"M", b"D") and SAFE_DIFF_PATH.fullmatch(relative):
            content_paths.append(relative)
    return groups, content_paths


def run_ref_update(restoregap: str, repo: Path, update: tuple[str, str, str, str], empty_tree: bytes) -> None:
    local_ref, local_oid, remote_ref, remote_oid = update
    kind = ref_kind(local_oid, remote_oid, remote_ref, repo)
    branch = remote_ref.startswith("refs/heads/")

    if kind == "delete":
        old_tree = resolve_tree(repo, remote_oid, branch=branch)
        new_tree = empty_tree
    elif kind == "create":
        old_tree = empty_tree
        new_tree = resolve_tree(repo, local_oid, branch=branch)
    else:
        old_tree = resolve_tree(repo, remote_oid, branch=branch)
        new_tree = resolve_tree(repo, local_oid, branch=branch)

    command_intent: dict[str, object] = {
        "version": 2,
        "action": "run_command",
        "paths": [str(repo)],
        "command": f"git push {kind} {remote_ref}",
        "actor": "git/pre-push",
        "context_window": "git-pre-push",
        "description": "evaluated outgoing Git ref update",
    }
    run_preflight(restoregap, repo, intent=command_intent)

    path_groups, content_paths = changed_path_groups(repo, old_tree, new_tree)
    for action, paths in path_groups.items():
        if paths:
            run_preflight(
                restoregap,
                repo,
                intent={
                    "version": 2,
                    "action": action,
                    "paths": paths,
                    "actor": "git/pre-push",
                    "context_window": "git-pre-push",
                    "description": "authoritative NUL-delimited outgoing tree paths",
                },
            )

    if content_paths:
        try:
            diff_result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "diff",
                    "--patch",
                    "--src-prefix=a/",
                    "--dst-prefix=b/",
                    "--no-color",
                    "--no-relative",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--ignore-submodules=none",
                    "--no-renames",
                    old_tree.decode("ascii"),
                    new_tree.decode("ascii"),
                    "--",
                    *[f":(literal){path}" for path in content_paths],
                ],
                cwd=repo,
                env=git_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as exc:
            raise GateError(f"cannot compute ref tree diff: {exc.strerror or type(exc).__name__}") from None
        if diff_result.returncode != 0:
            raise GateError("Git could not compute the outgoing ref tree diff")
        if diff_result.stdout:
            run_preflight(restoregap, repo, diff=diff_result.stdout)


def parse_updates(data: bytes, repo: Path, oid_length: int) -> list[tuple[str, str, str, str]]:
    if b"\x00" in data:
        raise GateError("malformed ref update input")
    if not data:
        return []
    updates: list[tuple[str, str, str, str]] = []
    destinations: set[str] = set()
    for raw_line in data.splitlines():
        try:
            line = raw_line.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise GateError("malformed ref update input") from None
        fields = line.split(" ")
        if len(fields) != 4 or any(not field or "\t" in field for field in fields):
            raise GateError("malformed ref update input")
        local_ref, local_oid, remote_ref, remote_oid = fields
        local_deleted = validate_oid(local_oid, oid_length)
        validate_oid(remote_oid, oid_length)
        validate_ref(repo, local_ref, local=True, deleting=local_deleted, local_oid=local_oid)
        validate_ref(repo, remote_ref)
        if remote_ref in destinations:
            raise GateError("duplicate destination ref in hook input")
        destinations.add(remote_ref)
        updates.append((local_ref, local_oid.lower(), remote_ref, remote_oid.lower()))
    return updates


def main() -> int:
    if len(sys.argv) != 3:
        print("restoregap pre-push: invalid Git hook arguments", file=sys.stderr)
        return 2
    try:
        repo = discover_repo()
        restoregap = shutil.which("restoregap")
        if not restoregap:
            raise GateError("restoregap executable is missing from PATH")
        validate_policy_location(repo)
        oid_length, empty_tree = object_format(repo)
        updates = parse_updates(sys.stdin.buffer.read(), repo, oid_length)
        for update in updates:
            run_ref_update(restoregap, repo, update, empty_tree)
    except (GateError, OSError, UnicodeError) as exc:
        print(f"restoregap pre-push: {exc}", file=sys.stderr)
        return 2
    print(f"restoregap pre-push: evaluated {len(updates)} ref update(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
