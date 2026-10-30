#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Restore Gap contributors
"""End-to-end coverage for the provider-neutral Git pre-push adapter."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "scripts/git-pre-push-restoregap.py"


class GitPrePushRestoreGapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="restoregap-git-pre-push-")
        cls.temp_root = Path(cls.temp.name)
        cls.bin_dir = cls.temp_root / "bin"
        cls.bin_dir.mkdir()
        cls.restoregap = cls.bin_dir / "restoregap"
        result = subprocess.run(
            ["go", "build", "-o", str(cls.restoregap), "./cmd/restoregap"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"could not build RestoreGap for integration test: {result.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.root = self.temp_root / self._testMethodName
        self.root.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.context = self.root / "policy.yml"
        self.ledger = self.root / "ledger.jsonl"
        self.state = self.root / "state"
        self.artifact = self.root / "artifact"
        self.source = self.root / "recovery-source"
        self.artifact.write_text("fixture recovery bytes\n")
        self.source.write_text("fixture recovery bytes\n")
        self._git("init", "-q")
        self._git("config", "user.email", "fixture@example.invalid")
        self._git("config", "user.name", "RestoreGap fixture")
        (self.repo / "tracked.txt").write_text("initial state\n")
        self._git("add", "tracked.txt")
        self._git("commit", "-qm", "initial")
        self.base_oid = self._git("rev-parse", "HEAD").strip()
        self._write_policy()
        self._run_restoregap("drill", "--context", str(self.context), "--ledger", str(self.ledger))
        if "verified: true" not in self.context.read_text():
            raise AssertionError("real drill did not write a verified proof")
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{self.bin_dir}:{os.environ.get('PATH', '')}",
                "RESTOREGAP_CONTEXT": str(self.context),
                "RESTOREGAP_LEDGER": str(self.ledger),
                "XDG_STATE_HOME": str(self.state),
            }
        )

    def _git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"git {args[0]} failed: {result.stderr}")
        return result.stdout

    def _run_restoregap(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin_dir}:{os.environ.get('PATH', '')}",
                "RESTOREGAP_CONTEXT": str(self.context),
                "RESTOREGAP_LEDGER": str(self.ledger),
                "XDG_STATE_HOME": str(self.state),
            }
        )
        result = subprocess.run(
            [str(self.restoregap), *args],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"restoregap {args[0]} failed: {result.stderr}\n{result.stdout}")
        return result

    def _write_policy(self) -> None:
        # JSON string quoting is valid YAML and keeps fixture paths unambiguous.
        repo = self.repo.resolve().as_posix()
        artifact = json_quote(self.artifact.as_posix())
        source = json_quote(self.source.as_posix())
        path = json_quote(repo)
        recursive = json_quote(repo + "/**")
        guards = """  - id: repo-files
    kind: lifeline
    match:
      paths: [%s, %s]
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
  - id: push-command
    kind: guard
    match:
      commands:
        - "git push create refs/heads/*"
        - "git push update refs/heads/*"
        - "git push rewrite refs/heads/*"
        - "git push delete refs/heads/*"
        - "git push create refs/tags/*"
        - "git push rewrite refs/tags/*"
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
""" % (path, recursive)
        self.context.write_text(
            "version: 2\nguards:\n" + guards + "drills:\n"
            "  - proof: repo-recovery\n"
            f"    artifact: {artifact}\n"
            f"    recovery_source: {source}\n"
            f"    recover: {json_quote(f'cp \"{self.source}\" \"$RG_TARGET\"')}\n"
            "proofs:\n  - id: repo-recovery\n"
            f"    command: {json_quote('cp recovery source into RG_TARGET')}\n"
            "    status: observed\n    verified: false\n"
            "    observed_at: \"2026-01-01T00:00:00Z\"\n"
        )

    def _write_path_policy(self, paths: list[Path]) -> None:
        existing = self.context.read_text()
        drill_tail = existing.split("drills:", 1)[1]
        resolved_repo = self.repo.resolve()
        repo = json_quote(resolved_repo.as_posix())
        exact_paths = ", ".join(
            json_quote(str(resolved_repo / path.relative_to(self.repo))) for path in paths
        )
        commands = "\n".join(
            f'        - "git push {kind} refs/heads/*"'
            for kind in ("create", "update", "rewrite", "delete")
        )
        commands += '\n        - "git push create refs/tags/*"\n        - "git push rewrite refs/tags/*"\n        - "git push delete refs/tags/*"'
        guards = f"""version: 2
guards:
  - id: repo-root
    kind: guard
    match:
      paths: [{repo}]
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
  - id: exact-tree-paths
    kind: lifeline
    match:
      paths: [{exact_paths}]
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
  - id: push-command
    kind: guard
    match:
      commands:
{commands}
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
drills:{drill_tail}"""
        self.context.write_text(guards)

    def _invoke_hook(
        self,
        data: bytes,
        *,
        remote: str = "origin",
        url: str = "https://user:secret@example.invalid/repo",
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(ADAPTER), remote, url],
            cwd=self.repo,
            env=env or self.env,
            input=data,
            capture_output=True,
            check=False,
        )

    def _record(self, local_ref: str, local_oid: str, remote_ref: str, remote_oid: str) -> bytes:
        return f"{local_ref} {local_oid} {remote_ref} {remote_oid}\n".encode()

    def test_create_update_rewrite_and_delete_refs_are_evaluated(self) -> None:
        zeros = "0" * len(self.base_oid)

        created = self._invoke_hook(self._record("refs/heads/feature", self.base_oid, "refs/heads/feature", zeros))
        self.assertEqual(created.returncode, 0, created.stderr.decode() + created.stdout.decode())
        self.assertIn(b"evaluated 1 ref update", created.stdout)

        (self.repo / "tracked.txt").write_text("fast-forward state\n")
        self._git("commit", "-qam", "fast-forward")
        update_oid = self._git("rev-parse", "HEAD").strip()
        updated = self._invoke_hook(self._record("refs/heads/feature", update_oid, "refs/heads/feature", self.base_oid))
        self.assertEqual(updated.returncode, 0, updated.stderr.decode())

        self._git("checkout", "-q", self.base_oid)
        (self.repo / "tracked.txt").write_text("divergent state\n")
        self._git("commit", "-qam", "divergent")
        rewrite_oid = self._git("rev-parse", "HEAD").strip()
        rewritten = self._invoke_hook(self._record("refs/heads/feature", rewrite_oid, "refs/heads/feature", update_oid))
        self.assertEqual(rewritten.returncode, 0, rewritten.stderr.decode())

        deleted = self._invoke_hook(self._record("refs/heads/feature", zeros, "refs/heads/feature", update_oid))
        self.assertEqual(deleted.returncode, 0, deleted.stderr.decode())

        self._git("tag", "-a", "v1", "-m", "fixture tag", self.base_oid)
        tag_oid = self._git("rev-parse", "refs/tags/v1").strip()
        tag_created = self._invoke_hook(self._record("refs/tags/v1", tag_oid, "refs/tags/v1", zeros))
        self.assertEqual(tag_created.returncode, 0, tag_created.stderr.decode())

        self._git("tag", "-a", "v2", "-m", "replacement tag", "HEAD")
        replacement_tag_oid = self._git("rev-parse", "refs/tags/v2").strip()
        tag_rewritten = self._invoke_hook(self._record("refs/tags/v2", replacement_tag_oid, "refs/tags/v1", tag_oid))
        self.assertEqual(tag_rewritten.returncode, 0, tag_rewritten.stderr.decode())

        blob_oid = self._git("hash-object", "-w", "tracked.txt").strip()
        unsupported = self._invoke_hook(self._record("refs/tags/blob", blob_oid, "refs/tags/blob", zeros))
        self.assertEqual(unsupported.returncode, 2)
        self.assertIn(b"could not resolve", unsupported.stderr)

    def test_real_git_hook_protocol_and_existing_stdin_consumer(self) -> None:
        remote = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        hook_dir = self.root / "hooks"
        hook_dir.mkdir()
        existing = hook_dir / "pre-push-existing"
        existing.write_text("#!/bin/sh\ncat > \"$RESTOREGAP_HOOK_INPUT_LOG\"\n")
        existing.chmod(0o700)
        hook = hook_dir / "pre-push"
        hook.write_text(
            "#!/bin/sh\nset -eu\numask 077\n"
            'input="$(mktemp "${TMPDIR:-/tmp}/restoregap-hook-chain.XXXXXX")"\n'
            "trap 'rm -f \"$input\"' EXIT HUP INT TERM\n"
            'cat > "$input"\n'
            f'{shlex.quote(str(existing))} "$@" < "$input"\n'
            f'{shlex.quote(sys.executable)} {shlex.quote(str(ADAPTER))} "$@" < "$input"\n'
        )
        hook.chmod(0o700)
        input_log = self.root / "existing-hook-input"
        self._git("config", "core.hooksPath", str(hook_dir))
        self._git("remote", "add", "origin", str(remote))
        push_env = self.env.copy()
        push_env["RESTOREGAP_HOOK_INPUT_LOG"] = str(input_log)

        def push(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["git", "-C", str(self.repo), "push", *args],
                env=push_env,
                capture_output=True,
                text=True,
                check=False,
            )

        created = push("origin", "HEAD:refs/heads/feature")
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        self.assertIn("refs/heads/feature", self._git("--git-dir", str(remote), "show-ref"))
        self.assertEqual(len(input_log.read_text().splitlines()), 1)

        (self.repo / "tracked.txt").write_text("updated over Git protocol\n")
        self._git("commit", "-qam", "protocol update")
        updated_oid = self._git("rev-parse", "HEAD").strip()
        updated = push("origin", f"{updated_oid}:refs/heads/feature")
        self.assertEqual(updated.returncode, 0, updated.stderr + updated.stdout)

        deleted = push("origin", ":refs/heads/feature")
        self.assertEqual(deleted.returncode, 0, deleted.stderr + deleted.stdout + input_log.read_text())
        refs = subprocess.run(
            ["git", "--git-dir", str(remote), "show-ref"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotIn("refs/heads/feature", refs.stdout)

    def test_nul_paths_cover_quoted_binary_symlink_type_and_mode_changes(self) -> None:
        regular = self.repo / "type-change"
        regular.write_text("regular file before type change\n")
        self._git("add", "type-change")
        self._git("commit", "-qm", "regular type")
        old_oid = self._git("rev-parse", "HEAD").strip()

        os.chmod(self.repo / "tracked.txt", 0o755)
        regular.unlink()
        regular.symlink_to("tracked.txt")
        symlink = self.repo / "new-link"
        symlink.symlink_to("tracked.txt")
        odd_name = 'binary space\nquote"é.bin'
        (self.repo / odd_name).write_bytes(b"\x00binary\xffpayload\n")
        self._git("add", "type-change", "new-link", odd_name, "tracked.txt")
        self._git("commit", "-qm", "mode, type, binary and quoted path changes")
        new_oid = self._git("rev-parse", "HEAD").strip()

        exact = [self.repo / "tracked.txt", regular, symlink, self.repo / odd_name]
        self._write_path_policy(exact)
        record = self._record("refs/heads/feature", new_oid, "refs/heads/feature", old_oid)
        self._git("config", "core.quotePath", "true")
        quoted = self._invoke_hook(record)
        self.assertEqual(quoted.returncode, 0, quoted.stderr.decode() + quoted.stdout.decode())
        self.assertIn(b"authoritative NUL-delimited outgoing tree paths", quoted.stdout)
        self.assertIn(json.dumps(str((self.repo / odd_name).resolve()), ensure_ascii=False).encode(), quoted.stdout)
        self.assertIn(b'"source": "diff"', quoted.stdout)

        self._git("config", "core.quotePath", "false")
        self._git("config", "diff.noprefix", "true")
        self._git("config", "diff.relative", "true")
        self._git("config", "diff.mnemonicPrefix", "true")
        self._git("config", "color.ui", "always")
        external_marker = self.root / "external-diff-ran"
        self._git("config", "diff.external", f"touch {external_marker}")
        configured = self._invoke_hook(record)
        self.assertEqual(configured.returncode, 0, configured.stderr.decode() + configured.stdout.decode())
        self.assertIn(b"authoritative NUL-delimited outgoing tree paths", configured.stdout)
        self.assertFalse(external_marker.exists(), "repository diff.external command must not run")

        self._git("rm", "--", odd_name)
        self._git("commit", "-qm", "delete quoted binary")
        deleted_oid = self._git("rev-parse", "HEAD").strip()
        deleted = self._invoke_hook(self._record("refs/heads/feature", deleted_oid, "refs/heads/feature", new_oid))
        self.assertEqual(deleted.returncode, 0, deleted.stderr.decode() + deleted.stdout.decode())
        self.assertIn(b"delete_file", deleted.stdout)

    def test_gitlink_change_is_not_hidden_by_repository_config(self) -> None:
        subrepo = self.root / "subrepo"
        subrepo.mkdir()
        def subgit(*args: str) -> str:
            result = subprocess.run(
                ["git", "-C", str(subrepo), *args],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise AssertionError(f"git {args[0]} failed: {result.stderr}")
            return result.stdout

        subgit("init", "-q")
        subgit("config", "user.email", "fixture@example.invalid")
        subgit("config", "user.name", "RestoreGap fixture")
        (subrepo / "content.txt").write_text("gitlink version one\n")
        subgit("add", "content.txt")
        subgit("commit", "-qm", "first gitlink target")
        first_target = subgit("rev-parse", "HEAD").strip()
        (self.repo / "vendor").mkdir()
        self._git("update-index", "--add", "--cacheinfo", f"160000,{first_target},vendor/module")
        self._git("commit", "-qm", "add gitlink")
        old_oid = self._git("rev-parse", "HEAD").strip()

        (subrepo / "content.txt").write_text("gitlink version two\n")
        subgit("commit", "-qam", "second gitlink target")
        second_target = subgit("rev-parse", "HEAD").strip()
        self._git("update-index", "--cacheinfo", f"160000,{second_target},vendor/module")
        self._git("commit", "-qm", "update gitlink")
        new_oid = self._git("rev-parse", "HEAD").strip()

        gitlink = self.repo / "vendor/module"
        self._write_path_policy([gitlink])
        self._git("config", "diff.ignoreSubmodules", "all")
        record = self._record("refs/heads/feature", new_oid, "refs/heads/feature", old_oid)
        result = self._invoke_hook(record)
        self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
        self.assertIn(json_quote(str(gitlink.resolve())).encode(), result.stdout)
        self.assertIn(b"authoritative NUL-delimited outgoing tree paths", result.stdout)

    def test_missing_proof_blocks_real_preflight(self) -> None:
        self._write_policy()
        zeros = "0" * len(self.base_oid)
        result = self._invoke_hook(self._record("refs/heads/feature", self.base_oid, "refs/heads/feature", zeros))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"blocked or could not evaluate", result.stderr)

    def test_unreadable_policy_fails_closed(self) -> None:
        env = self.env.copy()
        env["RESTOREGAP_CONTEXT"] = str(self.root / "missing-policy.yml")
        zeros = "0" * len(self.base_oid)
        result = self._invoke_hook(self._record("refs/heads/feature", self.base_oid, "refs/heads/feature", zeros), env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"missing or unreadable policy path", result.stderr)

    def test_policy_inside_pushed_repository_is_rejected(self) -> None:
        policy = self.repo / "restoregap.yml"
        policy.write_text("version: 2\nguards: []\n")
        env = self.env.copy()
        env["RESTOREGAP_CONTEXT"] = str(policy)
        zeros = "0" * len(self.base_oid)
        result = self._invoke_hook(self._record("refs/heads/feature", self.base_oid, "refs/heads/feature", zeros), env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"must be outside the pushed repository", result.stderr)

    def test_unavailable_git_object_fails_closed(self) -> None:
        missing = "f" * len(self.base_oid)
        zeros = "0" * len(self.base_oid)
        result = self._invoke_hook(self._record("refs/heads/feature", missing, "refs/heads/feature", zeros))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"could not resolve", result.stderr)

    def test_malformed_input_fails_closed_without_echoing_remote_url(self) -> None:
        result = self._invoke_hook(b"refs/heads/main not-an-oid refs/heads/main 0000\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"malformed ref update", result.stderr)
        self.assertNotIn(b"secret", result.stdout + result.stderr)

        mismatched_local_oid = self.base_oid[::-1]
        result = self._invoke_hook(
            self._record(mismatched_local_oid, self.base_oid, "refs/heads/feature", "0" * len(self.base_oid))
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"malformed ref update", result.stderr)

    def test_untrusted_ref_metacharacters_are_not_shell_expanded(self) -> None:
        marker = self.root / "injected"
        ref = "refs/heads/a;touch${IFS}" + str(marker)
        zeros = "0" * len(self.base_oid)
        result = self._invoke_hook(self._record("refs/heads/feature", self.base_oid, ref, zeros))
        self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
        self.assertFalse(marker.exists())
        self.assertNotIn(b"secret", result.stdout + result.stderr)

    def test_missing_binary_fails_closed(self) -> None:
        env = self.env.copy()
        env["PATH"] = "/usr/bin:/bin"
        result = subprocess.run(
            [sys.executable, str(ADAPTER), "origin", "unused-url"],
            cwd=self.repo,
            env=env,
            input=b"",
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"restoregap executable is missing", result.stderr)


def json_quote(value: str) -> str:
    # JSON strings are a strict, readable subset of YAML scalars.
    return json.dumps(value, ensure_ascii=True)


if __name__ == "__main__":
    unittest.main()
