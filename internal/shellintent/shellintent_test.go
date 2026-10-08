// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package shellintent

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// want is the part of an Operation a case asserts on. Command is compared only
// when set, so cases that care about classification stay short.
type want struct {
	action  string
	paths   []string
	targets []string
	remote  string
	command string
}

func check(t *testing.T, command string, wants ...want) {
	t.Helper()
	res := Parse(command)
	if res.Unparseable {
		t.Fatalf("Parse(%q) unparseable: %s", command, res.Reason)
	}
	if len(res.Ops) != len(wants) {
		t.Fatalf("Parse(%q) = %d ops, want %d: %+v", command, len(res.Ops), len(wants), res.Ops)
	}
	for i, w := range wants {
		got := res.Ops[i]
		if got.Action != w.action || !reflect.DeepEqual(nz(got.Paths), nz(w.paths)) || !reflect.DeepEqual(nz(got.Targets), nz(w.targets)) || got.Remote != w.remote || (w.command != "" && got.Command != w.command) {
			t.Errorf("Parse(%q) op %d = {%s %v %v remote=%q cmd=%q}, want {%s %v %v remote=%q cmd=%q}",
				command, i, got.Action, got.Paths, got.Targets, got.Remote, got.Command, w.action, w.paths, w.targets, w.remote, w.command)
		}
	}
}

func nz(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func del(paths ...string) want { return want{action: "delete_file", paths: paths} }
func mod(paths ...string) want { return want{action: "modify_file", paths: paths} }
func none() want               { return want{} }
func run(command string) want  { return want{action: "run_command", command: command} }
func remote(host, command string) want {
	return want{action: "run_command", remote: host, command: command}
}

func TestQuotingAndEscapes(t *testing.T) {
	check(t, `rm "my file.db"`, del("my file.db"))
	check(t, `rm 'a b'`, del("a b"))
	check(t, `rm a\ b`, del("a b"))
	check(t, `rm "a \"quoted\" b"`, del(`a "quoted" b`))
	check(t, `rm 'it'"'"'s'`, del("it's"))
	check(t, `rm $HOME/x ${DIR}/y`, del("$HOME/x", "${DIR}/y"))
	check(t, "rm x # not-a-path", del("x"))
	check(t, `rm a#b`, del("a#b"))
	// A quoted word is data, not a command and not an operator.
	check(t, `echo "rm -rf /"`, none())
	check(t, `echo 'rm x; rm y'`, none())
	check(t, `echo "a && rm x"`, none())
	check(t, `"rm" x`, del("x"))
	check(t, `\rm x`, del("x"))
	check(t, `/bin/rm -rf -- -weird`, del("-weird"))
}

func TestCompoundSplitting(t *testing.T) {
	check(t, `echo ok && rm -rf ~/Backups/x`, none(), del("~/Backups/x"))
	check(t, `false || rm x`, none(), del("x"))
	check(t, `echo a; rm x`, none(), del("x"))
	check(t, `cat f | xargs rm`, none(), run("xargs rm"))
	check(t, "echo a\nrm x", none(), del("x"))
	check(t, `sleep 1 & rm x`, none(), del("x"))
	check(t, `(cd /tmp; rm x)`, none(), del("x"))
	check(t, `{ rm x; }`, del("x"))
	check(t, `if true; then rm x; fi`, none(), del("x"))
	check(t, `for f in a b; do rm $f; done`, none(), del("$f"))
	check(t, `FOO=1 BAR=2 rm x`, del("x"))
	check(t, `FOO=1`)
	check(t, ``)
	check(t, "rm x \\\n y", del("x", "y"))
}

func TestCommandSubstitution(t *testing.T) {
	check(t, `echo $(rm x)`, del("x"), none())
	check(t, "echo `rm x`", del("x"), none())
	check(t, `echo "$(rm x)"`, del("x"), none())
	check(t, `echo '$(rm x)'`, none())
	check(t, `echo $(echo $(rm x))`, del("x"), none(), none())
	check(t, `echo $((1+2))`, none())
	check(t, `echo "$(echo "a b")"`, none(), none())
}

func TestTransparentPrefixes(t *testing.T) {
	check(t, `sudo -u app rm x`, del("x"))
	check(t, `sudo -- rm x`, del("x"))
	check(t, `sudo rm -rf /tmp/x`, del("/tmp/x"))
	check(t, `doas -u app rm x`, del("x"))
	check(t, `env FOO=1 nice -n 5 rm x`, del("x"))
	check(t, `env -i -u HOME rm x`, del("x"))
	check(t, `nohup time rm x`, del("x"))
	check(t, `timeout -s KILL -k 5 30 rm x`, del("x"))
	check(t, `command rm x`, del("x"))
	check(t, `exec rm x`, del("x"))
	check(t, `builtin rm x`, del("x"))
	check(t, `stdbuf -oL rm x`, del("x"))
	check(t, `/usr/bin/sudo /bin/rm x`, del("x"))
	// A bare prefix and a lookup are not wrappers around anything.
	check(t, `sudo`, none())
	check(t, `command -v rm`, none())
	// The prefix is gone from Command so a guard glob sees the real command.
	check(t, `sudo -u app git push --force`, run("git push --force"))
}

func TestShellDashC(t *testing.T) {
	check(t, `bash -lc "cd /tmp && rm -rf cache"`, none(), del("cache"))
	check(t, `sh -c 'rm x; rm y'`, del("x"), del("y"))
	check(t, `zsh -ec "rm x"`, del("x"))
	check(t, `bash -o pipefail -c "rm x"`, del("x"))
	check(t, `bash -c "bash -c 'rm x'"`, del("x"))
	// A script by path is not unwrapped.
	check(t, `bash cleanup.sh`, none())
}

func TestSSH(t *testing.T) {
	check(t, `ssh -p 2222 -i key nas docker rm restoregap-cloud`,
		want{action: "run_command", remote: "nas", command: "ssh nas docker rm restoregap-cloud"})
	check(t, `ssh root@nas uptime`, want{action: "run_command", remote: "nas", command: "ssh nas uptime"})
	check(t, `ssh -o StrictHostKeyChecking=no -oBatchMode=yes -tt nas sudo docker rm x`,
		remote("nas", "ssh nas docker rm x"))
	check(t, `ssh nas "docker volume rm restoregap-cloud_data && rm -rf /data"`,
		remote("nas", "ssh nas docker volume rm restoregap-cloud_data"),
		remote("nas", "ssh nas rm -rf /data"))
	check(t, `ssh -- nas rm /data/x`, remote("nas", "ssh nas rm /data/x"))
	// Remote redirects stay inside the remote command.
	check(t, `ssh nas "echo x > /etc/foo"`, remote("nas", "ssh nas echo x > /etc/foo"))
	// A local redirect on the ssh line is a local file write.
	check(t, `ssh nas uptime > out.txt`, remote("nas", "ssh nas uptime"), mod("out.txt"))
	// Nested wrappers keep every layer in Command.
	check(t, `ssh nas docker exec ctr rm /data/x`, want{action: "run_command", remote: "nas", command: "ssh nas docker exec ctr rm /data/x"})
	// No remote command means no wrapped operation.
	check(t, `ssh nas`, none())
	res := Parse(`ssh -p 2222 nas docker rm restoregap-cloud`)
	if len(res.Ops[0].Paths) != 0 {
		t.Errorf("remote op carries local paths: %v", res.Ops[0].Paths)
	}
}

func TestContainerExec(t *testing.T) {
	check(t, `docker exec -u 0 restoregap-cloud rm /data/cloud.db`,
		remote("restoregap-cloud", "docker exec restoregap-cloud rm /data/cloud.db"))
	check(t, `docker exec -it -e A=b -w /x ctr sh -c "rm a && rm b"`,
		remote("ctr", "docker exec ctr rm a"), remote("ctr", "docker exec ctr rm b"))
	check(t, `docker container exec ctr ls`, remote("ctr", "docker exec ctr ls"))
	check(t, `docker -H tcp://h:2375 exec ctr ls`, remote("ctr", "docker exec ctr ls"))
	check(t, `podman exec ctr rm x`, remote("ctr", "podman exec ctr rm x"))
	check(t, `docker compose exec -T web rm x`, remote("web", "docker compose exec web rm x"))
	check(t, `docker compose -f c.yml exec web rm x`, remote("web", "docker compose exec web rm x"))
	check(t, `docker-compose exec web rm x`, remote("web", "docker-compose exec web rm x"))
	check(t, `kubectl exec -n prod mypod -c app -- rm /data/x`, remote("mypod", "kubectl exec mypod rm /data/x"))
	check(t, `kubectl exec mypod -- sh -c "rm a; rm b"`, remote("mypod", "kubectl exec mypod rm a"), remote("mypod", "kubectl exec mypod rm b"))
	// exec with nothing to run is not a wrapper.
	check(t, `docker exec ctr`, none())
	check(t, `docker ps`, none())
}

func TestFileShapes(t *testing.T) {
	check(t, `rm proj/app.db`, del("proj/app.db"))
	check(t, `rm -rf proj`, del("proj"))
	check(t, `rm`, none())
	check(t, `shred -n 3 proj/app.db`, del("proj/app.db"))
	check(t, `unlink a`, del("a"))
	check(t, `rmdir a`, del("a"))
	check(t, `find /data -name '*.tmp' -delete`, del("/data"))
	check(t, `find /data /more -type f -exec rm {} ;`, del("/data", "/more"))
	check(t, `find . -execdir /bin/rm {} +`, del("."))
	check(t, `find /data -name x`, none())
	check(t, `find /data -exec ls {} ;`, none())
	check(t, `mv a b`, want{action: "move_file", paths: []string{"a"}, targets: []string{"b"}})
	check(t, `mv a b c/`, want{action: "move_file", paths: []string{"a", "b"}, targets: []string{"c/"}})
	check(t, `mv -t dst a b`, want{action: "move_file", paths: []string{"a", "b"}, targets: []string{"dst"}})
	check(t, `mv a`, none())
	check(t, `truncate -s0 proj/app.db`, mod("proj/app.db"))
	check(t, `truncate -s 0 proj/app.db`, mod("proj/app.db"))
	check(t, `dd if=/dev/zero of=proj/app.db bs=1 count=1`, mod("proj/app.db"))
	check(t, `dd if=a of=/dev/null`, none())
	check(t, `tee -a log.txt other.txt`, mod("log.txt", "other.txt"))
	check(t, `tee`, none())
	check(t, `cp -a src dst`, mod("dst"))
	check(t, `cp -t dst a b`, mod("dst"))
	check(t, `install -m 644 src dst`, mod("dst"))
	check(t, `rsync -a --delete src/ dst/`, mod("dst/"))
	check(t, `rsync -a -e "ssh -p 22" src/ dst/`, mod("dst/"))
	check(t, `chmod 600 a b`, mod("a", "b"))
	check(t, `chmod -R u+w dir`, mod("dir"))
	check(t, `chmod -x script`, mod("script"))
	check(t, `chown -R app:app dir`, mod("dir"))
	check(t, `chgrp staff a`, mod("a"))
	check(t, `chown --reference=ref a`, mod("a"))
	check(t, `chmod 600`, none())
	// A destination on another host is a command, never a local path.
	check(t, `cp a host:/tmp/b`, run("cp a host:/tmp/b"))
	check(t, `rsync -a src/ host:/tmp/dst/`, run("rsync -a src/ host:/tmp/dst/"))
}

func TestRedirections(t *testing.T) {
	check(t, `> file`, mod("file"))
	check(t, `>file`, mod("file"))
	check(t, `: > file`, mod("file"))
	check(t, `echo hi > out.txt`, none(), mod("out.txt"))
	check(t, `echo hi >> out.txt`, none(), mod("out.txt"))
	check(t, `echo hi >| out.txt`, none(), mod("out.txt"))
	check(t, `echo hi &> out.txt`, none(), mod("out.txt"))
	check(t, `rm x > /dev/null 2>&1`, del("x"))
	check(t, `rm x 2> err.log`, del("x"))
	check(t, `cat < in.txt`, none())
	check(t, `cat <<< "text"`, none())
	check(t, `echo hi 1> out.txt`, none(), mod("out.txt"))
	check(t, `echo ">" x`, none())
	check(t, `echo hi >&2`, none())
}

func TestRunShapes(t *testing.T) {
	positive := []string{
		`git push --force origin main`, `git push -f origin main`, `git push --force-with-lease origin main`,
		`git push --force-if-includes`, `git push origin +main`, `git -C /repo push -uf`,
		`git branch -D old`, `git reset --hard HEAD~1`, `git clean -fd`, `git clean -x`, `git clean -d`,
		`git stash drop`, `git stash clear`, `git checkout .`, `git checkout -- .`, `git restore .`,
		`terraform destroy`, `terraform apply -destroy`, `tofu destroy`, `pulumi destroy --yes`,
		`dropdb mydb`,
		`psql -c "DROP TABLE users"`, `psql -c "truncate users"`, `mysql -e "delete from t"`, `mariadb --execute="DROP DATABASE x"`,
		`sqlite3 app.db "DELETE FROM t"`,
		`redis-cli flushall`, `redis-cli -h host FLUSHDB`,
		`docker rm restoregap-cloud`, `docker rm --help`, `docker container rm x`, `docker container prune -f`,
		`docker volume rm v`, `docker volume prune`, `docker system prune -a`, `docker compose down -v`,
		`docker-compose down`, `docker stack rm s`, `podman rm x`, `podman volume rm v`, `podman system prune`,
		`docker -H tcp://h rm x`,
		`kubectl delete pod x`, `kubectl -n prod delete pod x`, `helm uninstall rel`, `helm delete rel`,
		`systemctl disable foo`, `systemctl --user mask foo`,
		`zfs destroy tank/data`, `zpool destroy tank`, `btrfs subvolume delete /mnt/sub`, `lvremove vg/lv`,
		`vgremove vg`, `wipefs -a /dev/sda`, `mkfs.ext4 /dev/sda1`, `mkfs /dev/sda1`, `sgdisk --zap-all /dev/sda`,
		`parted /dev/sda rm 1`, `parted /dev/sda mklabel gpt`,
		`restic forget --prune`, `restic -r /repo prune`, `borg prune repo`, `borg delete repo`, `borg compact repo`,
		`rclone delete r:x`, `rclone purge r:x`, `rclone sync a r:b`, `rclone move a r:b`, `rclone --config c sync a b`,
		`aws s3 rm s3://b/k`, `aws s3 rb s3://b`, `aws s3 sync . s3://b --delete`, `gsutil rm gs://b/k`, `gsutil -m rb gs://b`,
		`crontab -r`, `launchctl bootout gui/501/x`, `launchctl remove x`,
		`gh repo delete o/r`, `gh release delete v1`,
		`xargs rm`, `xargs -0 rm`, `xargs -0 -n1 rm -rf`, `xargs -I {} sudo rm {}`,
	}
	for _, c := range positive {
		res := Parse(c)
		if res.Unparseable || len(res.Ops) != 1 || res.Ops[0].Action != "run_command" {
			t.Errorf("Parse(%q) = %+v, want one run_command", c, res)
			continue
		}
		if res.Ops[0].Command != strings.Join(strings.Fields(c), " ") && !strings.ContainsAny(c, `"=`) {
			t.Errorf("Parse(%q) Command = %q", c, res.Ops[0].Command)
		}
		if len(res.Ops[0].Paths) != 0 {
			t.Errorf("Parse(%q) run_command carries paths %v; the caller anchors repo-scoped ones", c, res.Ops[0].Paths)
		}
	}
	negative := []string{
		`docker ps`, `docker run --rm alpine ls`, `docker volume ls`, `docker compose up -d`, `docker compose ps`,
		`git push`, `git push origin main`, `git push -u origin main`, `git status`, `git branch -d merged`, `git branch`,
		`git reset --soft HEAD~1`, `git clean -n`, `git clean -nfd`, `git stash`, `git stash list`, `git checkout main`,
		`git checkout -b feature`, `git restore file.txt`,
		`terraform plan`, `terraform apply`, `terraform plan -destroy`, `pulumi up`,
		`psql -c "select 1"`, `psql -c "select * from dropbox"`, `psql mydb`, `sqlite3 app.db ".tables"`, `mysql -e "show tables"`,
		`redis-cli get x`, `kubectl get pods`, `helm install rel chart`, `systemctl stop foo`, `systemctl restart foo`,
		`systemctl status foo`, `zfs list`, `btrfs subvolume list /`, `crontab -l`, `launchctl list`,
		`rclone ls r:x`, `rclone copy a r:b`, `restic snapshots`, `borg list repo`, `aws s3 ls`, `aws s3 sync . s3://b`,
		`gsutil ls`, `gh repo view`, `gh release list`, `xargs echo`, `xargs -0 cat`, `parted /dev/sda print`, `sgdisk -p /dev/sda`,
		`ls -la`, `cat file`, `echo hi`, `uptime`,
	}
	for _, c := range negative {
		res := Parse(c)
		if res.Unparseable || len(res.Ops) != 1 || res.Ops[0].Action != "" {
			t.Errorf("Parse(%q) = %+v, want one unrecognized op", c, res)
		}
	}
}

func TestRepoScopedShapes(t *testing.T) {
	for c, scoped := range map[string]bool{
		`git push --force`: true, `terraform destroy`: true, `dropdb x`: true, `tofu destroy`: true, `pulumi destroy`: true,
		`docker rm x`: false, `kubectl delete pod x`: false,
	} {
		res := Parse(c)
		if len(res.Ops) != 1 || res.Ops[0].RepoScoped != scoped {
			t.Errorf("Parse(%q).RepoScoped = %+v, want %v", c, res.Ops, scoped)
		}
	}
	// Wrapped operations are never repo scoped; the repo is on another host.
	if res := Parse(`ssh nas git push --force`); res.Ops[0].RepoScoped || res.Ops[0].Remote != "nas" {
		t.Errorf("wrapped op = %+v", res.Ops[0])
	}
}

func TestWordsAreUnwrapped(t *testing.T) {
	res := Parse(`sudo -u app env A=1 rm -rf x`)
	if got := res.Ops[0].Words; !reflect.DeepEqual(got, []string{"rm", "-rf", "x"}) {
		t.Errorf("Words = %v", got)
	}
}

func TestUnparseable(t *testing.T) {
	cases := map[string]string{
		"unbalanced double":     `rm "my file`,
		"unbalanced single":     `rm 'my file`,
		"unbalanced subst":      `echo $(rm x`,
		"unbalanced backtick":   "echo `rm x",
		"unterminated heredoc":  "cat <<EOF\nrm x\n",
		"heredoc no newline":    "cat <<EOF",
		"heredoc wrong close":   "cat <<EOF\nx\nEOFX\n",
		"heredoc no delimiter":  "cat <<",
		"dash heredoc tabs":     "cat <<EOF\nx\n\tEOF\n",
		"process subst in":      `diff <(ls a) b`,
		"process subst out":     `tee >(cat) < x`,
		"too long":              "echo " + strings.Repeat("a", 64<<10),
		"too deep":              `echo $(echo $(echo $(echo $(echo $(echo hi)))))`,
		"unterminated in subst": "echo $(cat <<EOF\nx\n)",
	}
	for name, c := range cases {
		res := Parse(c)
		if !res.Unparseable || res.Reason == "" || res.Ops != nil {
			t.Errorf("%s: Parse = %+v, want Unparseable with a reason and no ops", name, res)
		}
	}
	// The boundary itself still parses.
	if res := Parse(`echo $(echo $(echo $(echo hi)))`); res.Unparseable {
		t.Errorf("3 levels of substitution should parse: %s", res.Reason)
	}
	if res := Parse(`echo $(echo $(echo $(echo $(echo hi))))`); res.Unparseable {
		t.Errorf("4 levels of substitution should parse: %s", res.Reason)
	}
	if res := Parse("echo " + strings.Repeat("a", 64<<10-5)); res.Unparseable {
		t.Errorf("input at the limit should parse: %s", res.Reason)
	}
	// A heredoc operator inside quotes is only text.
	if res := Parse(`echo "a << b"`); res.Unparseable {
		t.Errorf("quoted << should parse: %s", res.Reason)
	}
}

// nest wraps command in n layers of a quoting wrapper, each of which the parser
// must re-parse as a string.
func nest(command string, n int, wrap func(string) string) string {
	for i := 0; i < n; i++ {
		command = wrap(command)
	}
	return command
}

func TestWrapperStringsConsumeDepth(t *testing.T) {
	wrappers := map[string]func(string) string{
		"ssh":     func(c string) string { return "ssh h " + strconv.Quote(c) },
		"bash -c": func(c string) string { return "bash -c " + strconv.Quote(c) },
	}
	for name, wrap := range wrappers {
		if res := Parse(nest("rm x", 3, wrap)); res.Unparseable || len(res.Ops) != 1 {
			t.Errorf("%s x3 should parse, got %+v", name, res)
		}
		if res := Parse(nest("rm x", 6, wrap)); !res.Unparseable {
			t.Errorf("%s x6 should be unparseable, got %+v", name, res.Ops)
		}
	}
}

// FuzzParse holds the package's one hard promise: any input yields a Result
// without panicking, and a failed parse never carries operations.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{`rm "a b"`, `ssh h 'rm x; $(rm y)'`, "cat <<EOF", `echo $(echo "$(rm x)")`, "bash -c 'a' > f", `docker exec -it c sh -c "x"`, "cat <<EOF\n$(rm x)\nEOF", "cd /a && (cd b; rm c) | cat", "echo $(cat <<'E'\n)\nE\n)", `\`, `"`, `$(`, "`", `>`, `2>&`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		res := Parse(s)
		if res.Unparseable && (res.Ops != nil || res.Reason == "") {
			t.Fatalf("Parse(%q) = %+v", s, res)
		}
		for _, op := range res.Ops {
			if op.Remote != "" && (op.Action != "run_command" || len(op.Paths) != 0 || op.Dir != "") {
				t.Fatalf("Parse(%q): wrapped op must be a path-free run_command: %+v", s, op)
			}
		}
	})
}

func TestHeredocs(t *testing.T) {
	// The common agent commit command: the body, with its apostrophes and
	// parentheses, is text, and what follows the closing paren still runs.
	commit := "git commit -m \"$(cat <<'EOF'\nFix the thing (it's broken)\n\nrm -rf /\nEOF\n)\""
	check(t, commit, none(), none())
	check(t, commit+" && rm guarded", none(), none(), del("guarded"))
	check(t, "cat <<EOF\nrm -rf /\nEOF", none())
	check(t, "cat <<'EOF'\nrm -rf /\nEOF", none())
	check(t, "cat <<\"EOF\"\nrm -rf /\nEOF", none())
	check(t, "cat <<\\EOF\nrm -rf /\nEOF", none())
	// <<- ignores leading tabs on the closing line only.
	check(t, "cat <<-EOF\n\trm x\n\tEOF\nrm y", none(), del("y"))
	// The rest of the operator's line is still parsed.
	check(t, "cat <<EOF | tee x\nbody\nEOF", none(), mod("x"))
	check(t, "cat <<EOF > out.txt\nbody\nEOF", none(), mod("out.txt"))
	check(t, "cat <<EOF && rm y\nbody\nEOF", none(), del("y"))
	check(t, "cat <<EOF\nbody\nEOF\nrm y", none(), del("y"))
	check(t, "cat <<A <<B\none\nA\ntwo\nB\nrm y", none(), del("y"))
}

func TestHeredocBodySubstitutionsStillRun(t *testing.T) {
	// An unquoted delimiter leaves the body subject to substitution, so $(rm x)
	// in it executes; a quoted one does not.
	check(t, "cat <<EOF\nhello $(rm x)\nEOF", del("x"), none())
	check(t, "cat <<EOF\nhello `rm x`\nEOF", del("x"), none())
	check(t, "cat <<EOF\nhello \\$(rm x)\nEOF", none())
	check(t, "cat <<'EOF'\nhello $(rm x)\nEOF", none())
}

func TestDir(t *testing.T) {
	dirs := func(command string) []string {
		t.Helper()
		res := Parse(command)
		if res.Unparseable {
			t.Fatalf("Parse(%q) unparseable: %s", command, res.Reason)
		}
		var out []string
		for _, op := range res.Ops {
			if op.Action == "delete_file" {
				out = append(out, op.Dir)
			}
		}
		return out
	}
	cases := []struct {
		command string
		want    []string
	}{
		{`rm x`, []string{""}},
		{`cd /guarded && rm -rf *`, []string{"/guarded"}},
		{`cd /a; cd b; rm x`, []string{"/a/b"}},
		{`cd sub && rm x`, []string{"sub"}},
		{`cd sub && cd .. && rm x`, []string{"."}},
		{"cd /a\nrm x", []string{"/a"}},
		{`cd /a || rm x`, []string{"/a"}},
		{`cd /a && cd ~ && rm x`, []string{""}},
		{`cd /a && cd && rm x`, []string{""}},
		{`cd /a && cd - && rm x`, []string{""}},
		{`cd /a && pushd /b && rm x`, []string{"/b"}},
		{`cd /a && pushd /b && popd && rm x`, []string{""}},
		{`cd ~/work && rm x`, []string{"~/work"}},
		{`cd $HOME/x && rm y`, []string{""}},
		{`cd "/with space" && rm x`, []string{"/with space"}},
		{`cd -P /a && rm x`, []string{"/a"}},
		// A pipe, a background job and a subshell do not move the line.
		{`cd /a | rm x`, []string{""}},
		{`echo | cd /a; rm x`, []string{""}},
		{`cd /a & rm x`, []string{""}},
		{`(cd /a; rm x); rm y`, []string{"/a", ""}},
		{`cd /a && (cd /b && rm x) && rm y`, []string{"/b", "/a"}},
		// Substitutions start where the line has reached, and do not leak.
		{`cd /a && echo $(rm x) && rm y`, []string{"/a", "/a"}},
		{`echo $(cd /a; rm x); rm y`, []string{"/a", ""}},
		{`cd /a && bash -c "rm x" && rm y`, []string{"/a", "/a"}},
		{`bash -c "cd /b && rm x"; rm y`, []string{"/b", ""}},
	}
	for _, c := range cases {
		if got := dirs(c.command); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Dir of deletes in %q = %q, want %q", c.command, got, c.want)
		}
	}
	// Redirect writes take the directory too, and wrapped operations never do.
	res := Parse(`cd /a && echo x > out`)
	if got := res.Ops[len(res.Ops)-1]; got.Action != "modify_file" || got.Dir != "/a" {
		t.Errorf("redirect op = %+v", got)
	}
	if got := Parse(`cd /a && ssh nas rm x`).Ops[1]; got.Dir != "" || got.Remote != "nas" {
		t.Errorf("wrapped op = %+v", got)
	}
}

func TestBenign(t *testing.T) {
	benign := []string{
		`cd /tmp`, `pushd /tmp`, `popd`, `echo hi`, `printf '%s' x`, `true`, `false`, `test -f x`, `[ -f x ]`, `[[ -f x ]]`,
		`export A=1`, `unset A`, `set -e`, `read x`, `type ls`, `which ls`, `command -v ls`, `pwd`, `exit 1`, `return`, `source env.sh`, `. env.sh`,
		`ls -la`, `cat f`, `head f`, `tail -f f`, `less f`, `more f`, `wc -l f`, `sort f`, `uniq f`, `cut -d: -f1 f`, `tr a b`,
		`grep x f`, `egrep x f`, `fgrep x f`, `rg x`, `awk '{print}' f`, `sed -n 1p f`, `find . -name x`, `diff a b`, `stat f`,
		`file f`, `du -sh .`, `df -h`, `date`, `uname -a`, `hostname`, `whoami`, `id`, `env`, `env -i`, `sleep 1`,
		`git status`, `git log --oneline`, `git diff`, `git show HEAD`, `git branch`, `git branch -a`, `git rev-parse HEAD`, `git fetch`,
		`git ls-files`, `git grep x`, `git blame f`, `git describe`, `git tag`, `git remote -v`, `git stash list`, `git -C /repo status`,
	}
	for _, c := range benign {
		res := Parse(c)
		if res.Unparseable || len(res.Ops) != 1 || res.Ops[0].Action != "" || !res.Ops[0].Benign {
			t.Errorf("Parse(%q) = %+v, want one benign unrecognized op", c, res)
		}
	}
	notBenign := []string{
		`tee x`, `sed -i s/a/b/ f`, `sed -i.bak s/a/b/ f`, `sed --in-place s/a/b/ f`, `sed -ni p f`, `find . -delete`, `find . -exec ls {} ;`,
		`env FOO=1 mystery`, `command mystery`, `git branch -d x`, `git tag -d v1`, `git push`, `git commit -m x`, `git remote add x y`,
		`git stash`, `git stash pop`, `mystery`, `docker ps`, `eval x`, `python -c x`, `./run.sh`, `bash run.sh`, `ssh nas ls`,
	}
	for _, c := range notBenign {
		res := Parse(c)
		if res.Unparseable || len(res.Ops) == 0 || res.Ops[0].Benign {
			t.Errorf("Parse(%q) = %+v, want not benign", c, res)
		}
	}
}
