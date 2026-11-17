# Platforms and data locations

LabSecurity keeps **one data root per user**, following each OS convention. Nothing is written inside the repositories
you scan nor inside LabSecurity's own repository.

## Where things go

| | Linux and WSL2 | macOS | Any OS with `LABSEC_HOME=<dir>` |
| --- | --- | --- | --- |
| Data root (reports, runs, backups) | `${XDG_DATA_HOME:-~/.local/share}/labsecurity` | `~/Library/Application Support/LabSecurity` | `<dir>` |
| Config and credentials (mode 700/600) | `${XDG_CONFIG_HOME:-~/.config}/labsecurity` | `<data root>/config` | `<dir>/config` |
| Work copies and tool caches | `${XDG_CACHE_HOME:-~/.cache}/labsecurity` | `<data root>/cache` | `<dir>/cache` |
| Heavy-analysis lock | `${XDG_STATE_HOME:-~/.local/state}/labsecurity` | `<data root>/state` | `<dir>/state` |

The Linux column is exactly where earlier versions already wrote, so an existing install keeps working with no
migration. Inside the data root:

```text
<data root>/
  reports/<repo>-<hash>/<UTC timestamp>/   report.json, report.md, pr-body.md   (from `labsec report`)
  runs/<repo>/<UTC timestamp>/             raw tool output and summary.json of each lap (mode 700)
  backups/<UTC timestamp>/                 database dumps (scripts/backup.sh)
```

- `<hash>` is the first 6 hex characters of the SHA-256 of the repository's absolute path, so two repositories called
  `api` never share a folder.
- `scripts/lib/paths.sh` (init and backup scripts) and `labsec/config.py` (the CLI) resolve these paths; a test keeps
  them identical.
- `LABSEC_CONFIG_DIR`, `LABSEC_DATA_DIR`, `LABSEC_CACHE_DIR`, `LABSEC_STATE_DIR` and `LABSEC_BACKUP_DIR` override a single
  location and win over `LABSEC_HOME`.
- Reports hold findings. `labsec report --out DIR` refuses a folder inside the scanned repository or inside LabSecurity.
