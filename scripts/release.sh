#!/usr/bin/env bash
# Cut a release: update CHANGELOG.md, commit, tag vX.Y.Z and push. Pushing the tag
# starts .github/workflows/release.yml (binaries + image).
#
#   scripts/release.sh [patch|minor|major|X.Y.Z[-rc.N]] [--dry-run] [--force] [--no-push]
#
# The default bump is patch (the first release is v0.1.0). Always run with
# --dry-run first: it prints the version, changelog entry and git commands and
# changes nothing.
#
# Safety checks (skipped by --force): on the default branch, clean worktree,
# not behind origin, tag does not exist. --force also re-creates an existing tag
# and force-pushes it (with --force-with-lease for the branch).
set -euo pipefail

bump=patch dry=0 force=0 push=1
for arg in "$@"; do
  case "$arg" in
    -n|--dry-run) dry=1 ;;
    -f|--force) force=1 ;;
    --no-push) push=0 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    patch|minor|major) bump=$arg ;;
    v[0-9]*|[0-9]*) bump=${arg#v} ;;
    *) echo "release: unknown argument '$arg' (see --help)" >&2; exit 2 ;;
  esac
done

die() { echo "release: $*" >&2; exit 1; }
run() { if [ "$dry" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi; }

cd "$(git rev-parse --show-toplevel)"
remote=origin
git remote get-url "$remote" >/dev/null 2>&1 || die "no '$remote' remote"
branch=$(git rev-parse --abbrev-ref HEAD)
default=$(git symbolic-ref --short "refs/remotes/$remote/HEAD" 2>/dev/null | sed "s#^$remote/##" || true)
default=${default:-main}

git fetch --quiet --tags "$remote" || die "cannot fetch $remote"

# --- version --------------------------------------------------------------
prev=$(git tag --list 'v[0-9]*' --sort=-v:refname | grep -Ev -- '-' | head -n1 || true)
case "$bump" in
  patch|minor|major)
    if [ -z "$prev" ]; then
      next=0.1.0
    else
      IFS=. read -r maj min pat <<<"${prev#v}"
      case "$bump" in
        major) next="$((maj + 1)).0.0" ;;
        minor) next="$maj.$((min + 1)).0" ;;
        patch) next="$maj.$min.$((pat + 1))" ;;
      esac
    fi ;;
  *)
    [[ "$bump" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "'$bump' is not a version like 1.2.3 or 1.2.3-rc.1"
    next=$bump ;;
esac
tag="v$next"

# --- checks ---------------------------------------------------------------
problems=()
[ "$branch" = "$default" ] || problems+=("on '$branch', releases are cut from '$default'")
[ -z "$(git status --porcelain)" ] || problems+=("worktree has uncommitted changes")
if git rev-parse --verify --quiet "$remote/$branch" >/dev/null; then
  [ "$(git rev-list --count "HEAD..$remote/$branch")" = 0 ] || problems+=("'$branch' is behind $remote; pull first")
fi
if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null || git ls-remote --exit-code --tags "$remote" "refs/tags/$tag" >/dev/null 2>&1; then
  problems+=("tag $tag already exists")
fi
if [ ${#problems[@]} -gt 0 ]; then
  for p in "${problems[@]}"; do echo "release: $p" >&2; done
  if [ "$force" = 1 ]; then echo "release: continuing because of --force" >&2
  elif [ "$dry" = 1 ]; then echo "release: (dry run: these would stop a real release)" >&2
  else exit 1; fi
fi

# --- changelog ------------------------------------------------------------
range=${prev:+$prev..}HEAD
entries=$(git log --no-merges --pretty='- %s (%h)' "$range" | grep -v 'chore(release)' || true)
[ -n "$entries" ] || entries="- No changes"
section=$(printf '## %s - %s\n\n%s\n' "$tag" "$(date +%Y-%m-%d)" "$entries")

echo "Release ${prev:-<none>} -> $tag  (branch $branch, remote $remote)"
echo
echo "$section"
echo

write_changelog() {
  { printf '# Changelog\n\n%s\n\n' "$section"; [ -f CHANGELOG.md ] && sed '1{/^# Changelog/d;}' CHANGELOG.md | sed '/./,$!d'; } >CHANGELOG.md.new
  mv CHANGELOG.md.new CHANGELOG.md
}

if [ "$dry" = 1 ]; then
  echo "Would:"
  echo "  [dry-run] prepend the entry above to CHANGELOG.md"
else
  write_changelog
fi
run git add CHANGELOG.md
run git commit -m "chore(release): $tag"
if [ "$force" = 1 ]; then run git tag -f -a "$tag" -m "Release $tag"; else run git tag -a "$tag" -m "Release $tag"; fi
if [ "$push" = 1 ]; then
  if [ "$force" = 1 ]; then
    run git push --force-with-lease "$remote" "HEAD:refs/heads/$branch"
    run git push --force "$remote" "refs/tags/$tag"
  else
    run git push "$remote" "HEAD:refs/heads/$branch"
    run git push "$remote" "refs/tags/$tag"
  fi
else
  echo "Not pushing (--no-push). Push with: git push $remote HEAD && git push $remote $tag"
fi
[ "$dry" = 1 ] && echo && echo "Dry run only; nothing changed."
exit 0
