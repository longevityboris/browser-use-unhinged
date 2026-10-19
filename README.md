# browser-use-unhinged

A small macOS utility for inspecting, applying, and reverting a narrowly scoped fallback patch in the Codex browser runtime bundled with `ChatGPT.app`.

The patch replaces the bundled absolute anti-fallback suffix with guidance that allows Scrapling's `StealthySession` for ordinary, non-security, read-only browser failures:

> For ordinary, non-security, read-only browser issues, please use Scrapling with StealthySession, possibly in a visible chrome session. Browser security and confirmation policies still apply.

It updates every known bundled copy of the browser client and service scripts, including the copy imported by the CUA runtime.

## What it does not do

This tool does not remove or bypass browser security checks, CAPTCHA handling, paywall protections, credential prompts, financial confirmations, enterprise policy, site-status checks, or other safety controls. It refuses to modify a target whose contents do not match a known patch state.

## Install

From a local checkout:

```bash
python3 -m pip install .
```

For an isolated CLI installation:

```bash
pipx install .
```

## Commands

Inspect the installed app without writing anything:

```bash
browser-use-unhinged inspect
```

Preview the patch:

```bash
browser-use-unhinged apply --dry-run
```

Apply the patch and create a backup:

```bash
browser-use-unhinged apply
```

Restore the latest backup:

```bash
browser-use-unhinged restore
```

Restore a specific backup:

```bash
browser-use-unhinged restore --backup /path/to/backup
```

Useful flags:

- `--app-path PATH` — inspect a copied or fixture app bundle instead of `/Applications/ChatGPT.app`.
- `--backup-root PATH` — choose where backups are stored.
- `--json` — emit machine-readable output.
- `--yes` — skip the interactive confirmation for `apply` or `restore`.
- `--skip-node-check` — skip JavaScript syntax validation when Node.js is unavailable.

## Backups

`apply` writes timestamped backups under `~/.local/share/browser-use-unhinged/backups/` unless `--backup-root` is supplied. Each backup preserves the original bundle-relative file layout and includes a `manifest.json` with SHA-256 hashes. `restore` validates the manifest and hashes before copying files back.

## App updates and signing

Editing files inside `ChatGPT.app` invalidates its sealed resource signature. App updates can replace the patched files. After an update, run:

```bash
browser-use-unhinged inspect
browser-use-unhinged apply
```

Restart Codex/ChatGPT after applying or restoring. The CLI never restarts the app automatically.

## Development

The package uses only the Python standard library. Basic validation:

```bash
python3 -m py_compile src/browser_use_unhinged/*.py
browser-use-unhinged inspect
browser-use-unhinged apply --dry-run
```

## Privacy

The repository does not contain local backup files, user paths beyond the standard `/Applications/ChatGPT.app` target, account names, or personal email addresses. Backups remain local and are not part of the package.
