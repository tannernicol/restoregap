# demo/demo.tape — the README demo, recorded with vhs (github.com/charmbracelet/vhs).
#
# Regenerate with `make demo`: it rebuilds the binary, recreates the fixture via
# demo/setup.sh, and records this tape to demo/demo.gif. The gif is committed so
# the README renders without a toolchain; the tape is committed so the gif is
# reproducible and never drifts from what the CLI actually prints.

Output demo/demo.gif

Set Shell bash
Set FontSize 15
Set Width 1080
Set Height 640
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "cp docs/examples/preflight-hook.sh /tmp/rg-demo/bin/preflight-hook.sh && chmod +x /tmp/rg-demo/bin/preflight-hook.sh && cd /tmp/rg-demo && export PATH=$PWD/bin:$PATH RESTOREGAP_LEDGER=$PWD/ledger.jsonl PS1='$ ' && clear"
Enter
Show

Type "# 1. Drift — zero config. Does the copy you'd restore from still match the live thing?"
Enter
Sleep 800ms
Type "restoregap check proj backup/proj"
Enter
Sleep 4s
Type "clear"
Enter

Type "# 2. Proof — measure the live artifact into a drill, then actually restore it in a sandbox."
Enter
Sleep 800ms
Type "restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml"
Enter
Sleep 1500ms
Type "# a coding agent tries: rm proj/app.db  (Claude Code PreToolUse hook → restoregap preflight)"
Enter
Sleep 600ms
Type `echo '{"tool_name":"Bash","tool_input":{"command":"rm proj/app.db"}}' | preflight-hook.sh; echo "exit=$?"`
Enter
Sleep 4500ms
Type "clear"
Enter
Type "restoregap drill"
Enter
Sleep 3500ms

Type "# 3. Gate — the same change is allowed now, and refused again the day that proof expires."
Enter
Sleep 800ms
Type `echo '{"tool_name":"Bash","tool_input":{"command":"rm proj/app.db"}}' | preflight-hook.sh; echo "exit=$?"`
Enter
Sleep 6s
