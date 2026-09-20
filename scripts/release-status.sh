#!/usr/bin/env bash
# release-status — one screen that says whether the newest release is lined up
# to publish. Every line is a live probe of git, GitHub, and the installed
# binary; nothing here trusts a note. Exit 0 iff every line is green.
#
# Pair with scripts/launch-bar.sh: the bar scores the PRODUCT, this scores the
# RELEASE PLUMBING around it (tags, export, assets, drafts, installed build).
set -euo pipefail
REPO="${RESTOREGAP_REPO:-$HOME/restoregap-oss}"
EXPORT_REPO="${RESTOREGAP_EXPORT_REPO:-$HOME/restoregap-public}"
GH_REPO="${RESTOREGAP_GH_REPO:-tannernicol/restoregap}"
BIN="${RESTOREGAP_BIN:-$HOME/bin/restoregap}"
RED=0
ok()  { printf '  ok    %-10s %s\n' "$1" "$2"; }
bad() { printf '  FAIL  %-10s %s\n' "$1" "$2"; RED=$((RED+1)); }

version="v$(tr -d '[:space:]' < "$REPO/VERSION")"
src_head=$(git -C "$REPO" rev-parse --short HEAD)
src_branch=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)
echo "release-status $version — $(date -u +%FT%TZ)"

# source: tag exists and is an ancestor of HEAD; unreleased commits are reported, not red
if git -C "$REPO" rev-parse -q --verify "refs/tags/$version" >/dev/null; then
  tag_sha=$(git -C "$REPO" rev-parse --short "$version^{commit}")
  if git -C "$REPO" merge-base --is-ancestor "$version" HEAD; then
    unreleased=$(git -C "$REPO" rev-list --count "$version..HEAD")
    if [ "$unreleased" = 0 ]; then ok source "$src_branch $src_head is $version"; else ok source "$version = $tag_sha; $src_branch $src_head is $unreleased commit(s) past it (unreleased)"; fi
  else bad source "$version ($tag_sha) is not an ancestor of $src_branch $src_head"; fi
else bad source "no tag $version in source (git tag -a $version <sha>)"; fi
if [ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then ok source "working tree clean"; else bad source "uncommitted tracked changes"; fi
upstream=$(git -C "$REPO" rev-parse --abbrev-ref '@{upstream}' 2>/dev/null || true)
if [ -n "$upstream" ]; then
  ahead=$(git -C "$REPO" rev-list --count "$upstream..HEAD")
  if [ "$ahead" = 0 ]; then ok source "pushed to $upstream"; else bad source "$ahead commit(s) not pushed to $upstream"; fi
else bad source "no upstream configured"; fi

# export: tag exists, README pin matches, scrub clean
if [ -d "$EXPORT_REPO/.git" ]; then
  exp_head=$(git -C "$EXPORT_REPO" rev-parse --short HEAD)
  if git -C "$EXPORT_REPO" tag --points-at HEAD | grep -qx "$version"; then ok export "$exp_head tagged $version"; else bad export "$exp_head is not tagged $version (run scripts/publish-export.sh)"; fi
  if grep -q "restoregap/$version/scripts/install.sh" "$EXPORT_REPO/README.md"; then ok export "README pins $version"; else bad export "README does not pin $version"; fi
else bad export "$EXPORT_REPO missing"; fi
if [ -x "$REPO/scripts/scrub-check.sh" ] && (cd "$REPO" && scripts/scrub-check.sh >/dev/null 2>&1); then ok scrub "scrub-check clean on HEAD"; else bad scrub "scrub-check failed on HEAD"; fi

# github: release for this tag, asset count, stray drafts, visibility
if command -v gh >/dev/null 2>&1; then
  rel=$(gh release view "$version" -R "$GH_REPO" --json isDraft,assets -q '[.isDraft, (.assets|length)] | @tsv' 2>/dev/null || true)
  if [ -n "$rel" ]; then
    draft=${rel%%	*}; assets=${rel##*	}
    if [ "${assets:-0}" -ge 5 ]; then ok github "$version has $assets assets"; else bad github "$version has only ${assets:-0} assets"; fi
    if [ "$draft" = true ]; then ok github "$version is a DRAFT (owner publishes: gh release edit $version -R $GH_REPO --draft=false)"; else ok github "$version is PUBLISHED"; fi
  else bad github "no release $version on $GH_REPO"; fi
  stray=$(gh release list -R "$GH_REPO" --json tagName,isDraft -q '.[] | select(.isDraft) | .tagName' 2>/dev/null | grep -vx "$version" | tr '\n' ' ' || true)
  if [ -z "${stray// /}" ]; then ok github "no stray drafts"; else bad github "stray drafts: ${stray}(gh release delete <tag> -R $GH_REPO --yes)"; fi
  vis=$(gh repo view "$GH_REPO" --json visibility -q .visibility 2>/dev/null || echo unknown)
  ok github "repo visibility $vis (owner flips: gh repo edit $GH_REPO --visibility public --accept-visibility-change-consequences)"
else bad github "gh not installed"; fi

# installed binary matches source HEAD, or differs from it only by non-Go commits
if [ -x "$BIN" ]; then
  inst=$("$BIN" --version 2>/dev/null | awk '{print $NF}')
  inst_sha=$(printf '%s' "$inst" | grep -oE '[0-9a-f]{7,}$' || true)
  if [ "$inst" = "${version#v}" ] || [ -n "$inst_sha" ] && [ "$inst_sha" = "$src_head" ]; then ok installed "$BIN reports $inst"
  elif [ -n "$inst_sha" ] && git -C "$REPO" merge-base --is-ancestor "$inst_sha" HEAD 2>/dev/null \
       && git -C "$REPO" diff --quiet "$inst_sha" HEAD -- '*.go' go.mod go.sum ui/ 2>/dev/null; then
    ok installed "$BIN reports $inst; only non-Go commits since"
  else bad installed "$BIN reports $inst, source HEAD is $src_head (restoregap-rebuild-latest)"; fi
else bad installed "$BIN missing"; fi

# launch bar: newest recorded row, must be today's and product-green
row=$(grep -m1 -E '^- [0-9]{4}-[0-9]{2}-[0-9]{2} ' "$REPO/LAUNCH_BAR.md" || true)
today=$(date -u +%F)
case "$row" in
  "- $today "*"product 13/13"*) ok bar "${row#- }" ;;
  "- $today "*) bad bar "${row#- } (product not green)" ;;
  *) bad bar "newest recorded score is not from $today: ${row#- } (run scripts/launch-bar.sh)" ;;
esac

echo
if [ "$RED" = 0 ]; then echo "READY — $version is lined up; publishing is the owner's action."; else echo "HOLD — $RED line(s) red above."; fi
exit $((RED > 0))
