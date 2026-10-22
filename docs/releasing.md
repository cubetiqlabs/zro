# Releasing

```bash
scripts/release.sh --dry-run        # review: next version, changelog entry, git commands
scripts/release.sh                  # patch bump (first release: v0.1.0)
scripts/release.sh minor            # or major, or an explicit 1.2.3 / 1.2.3-rc.1
```

The script prepends the commits since the last tag to `CHANGELOG.md`, commits
`chore(release): vX.Y.Z`, creates an annotated tag and pushes both. The pushed tag starts
[`release.yml`](../.github/workflows/release.yml), which publishes the archives and
`checksums.txt` to GitHub Releases and the multi-arch image to
`ghcr.io/cubetiqlabs/zro`. Tags containing `-` (such as `-rc.1`) are marked pre-release and do
not move the image's `latest` tag.

| Flag | Effect |
|---|---|
| `--dry-run`, `-n` | Print everything, change nothing |
| `--force`, `-f` | Skip the safety checks (default branch, clean worktree, not behind origin, tag unused); re-create an existing tag and force-push it (`--force-with-lease` for the branch) |
| `--no-push` | Commit and tag locally only |

Run it from an up-to-date `main`. `zro update` and the install scripts only see stable
releases, so a pre-release is a safe way to test the pipeline first.
