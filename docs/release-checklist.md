# Release Checklist

Use this checklist before tagging a ClawArmor release.

## 1. Scope

- Confirm the release version.
- Review merged PRs and security-sensitive changes.
- Confirm `package.json`, `package-lock.json`, `openclaw.plugin.json`, and `docs/changelog.md` agree on the release version.

## 2. Local Verification

Run:

```bash
npm run typecheck
npm test
npm run build
```

For security-sensitive changes, also run the relevant manual checks from `docs/manual-test-guide.md`.

## 3. Security Review

Review changes touching:

- `src/engine-fast/`
- `src/engine-slow/`
- `src/core-hooks/`
- `src/taint-tracker/`
- `prompts/`
- `claw-armor.config.json`

Check for:

- New bypass paths
- Unsafe defaults
- Missing negative tests
- Fail-open behavior that is not documented
- Logging or redaction regressions

## 4. Documentation

- Update `README.md` if behavior or installation changed.
- Update `docs/changelog.md`.
- Update `SECURITY.md` or `ROADMAP.md` if maintenance policy changed.

## 5. Tag and Publish

```bash
git tag vX.Y.Z
git push origin main --tags
```

Then create a GitHub release using the changelog section for that version.
