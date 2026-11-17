# Backup and restore

## What is backed up

| Item | How | File |
|---|---|---|
| SonarQube database | `pg_dump -Fc` inside `sonar-db` | `sonarqube.dump` |
| DefectDojo database (findings, history, false positives, accepted risks) | `pg_dump -Fc` inside `dd-db` | `defectdojo.dump` |
| DefectDojo media (uploaded files) | `tar` of the `labsecurity_dd_media` volume | `defectdojo-media.tgz` |

Not backed up (rebuilt automatically): SonarQube Elasticsearch indexes (`sonar_data`), Valkey, scanner caches.

Destination: `<data root>/backups/<UTC timestamp>/` (directory mode 700, files 600), with a `SHA256SUMS` file. The data root
is `${XDG_DATA_HOME:-~/.local/share}/labsecurity` on Linux and WSL2, `~/Library/Application Support/LabSecurity` on macOS,
or `$LABSEC_HOME` when set (see [PLATFORMS.md](PLATFORMS.md)). The 14 newest backups are kept; older ones go to the desktop
trash when `gio trash` exists and are otherwise removed.
Backups contain finding details: never copy them into a repository.

## Manual backup

```bash
scripts/backup.sh            # keeps 14
scripts/backup.sh --keep 30
```

If the lab is stopped the script logs `skipped: lab is not running` and exits 0.

## Daily schedule (optional)

The backup is a plain script, so any scheduler works. Pick the one your OS has.

### Linux: systemd user timer (optional)

Linux only. Install once, from the clone:

```bash
mkdir -p ~/.config/systemd/user
ln -sf "$PWD/systemd/labsecurity-backup.service" "$PWD/systemd/labsecurity-backup.timer" ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now labsecurity-backup.timer
```

It runs daily at 13:30 local time (`Persistent=true` catches up after the machine was off). When the lab is stopped it
only logs the skip. Logs: `journalctl --user -u labsecurity-backup.service`. The units must be **symlinks** into the clone
(not copies): the service resolves its own link to find `scripts/backup.sh`, so nothing in the repository names your path.
If the clone lives on a drive that is not always mounted, the run fails until it is. Check with
`systemd-analyze --user verify ~/.config/systemd/user/labsecurity-backup.service`.

### macOS: launchd, or cron on any Unix

launchd: save this as `~/Library/LaunchAgents/labsecurity.backup.plist`, replacing `<LABSECURITY_DIR>` with the clone path,
then run `launchctl load ~/Library/LaunchAgents/labsecurity.backup.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>labsecurity.backup</string>
  <key>ProgramArguments</key><array>
    <string><LABSECURITY_DIR>/scripts/backup.sh</string><string>--keep</string><string>14</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string></dict>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>13</integer><key>Minute</key><integer>30</integer></dict>
</dict></plist>
```

cron (macOS, Linux, WSL2): `crontab -e` and add `30 13 * * * <LABSECURITY_DIR>/scripts/backup.sh --keep 14`.

Neither alternative was run on a Mac for this document (UNVERIFIED); the script itself is bash 3.2 compatible and uses
`shasum -a 256` when `sha256sum` is missing.

## Verify a backup

```bash
d="<data root>/backups/<timestamp>"
(cd "$d" && sha256sum -c SHA256SUMS)
docker compose exec -T dd-db pg_restore --list < "$d/defectdojo.dump" | head
```

## Restore

Restoring replaces the current data. Stop the applications first, keep the databases running.

```bash
d="<data root>/backups/<timestamp>"
docker compose stop sonarqube dd-nginx dd-uwsgi dd-celeryworker dd-celerybeat

# SonarQube
docker compose exec -T sonar-db pg_restore -U sonarqube -d sonarqube --clean --if-exists --no-owner < "$d/sonarqube.dump"

# DefectDojo
docker compose exec -T dd-db pg_restore -U defectdojo -d defectdojo --clean --if-exists --no-owner < "$d/defectdojo.dump"
docker run --rm -i -v labsecurity_dd_media:/media alpine:3.24.4 tar -C /media -xzf - < "$d/defectdojo-media.tgz"

docker compose up -d --wait
bin/scan --doctor
```

SonarQube rebuilds its search indexes on start after a restore; the first start takes longer.
The credential files in the config folder (`~/.config/labsecurity/` on Linux, `<data root>/config` on macOS) must be the ones that match the restored data
(the DefectDojo `DD_SECRET_KEY` and `DD_CREDENTIAL_AES_256_KEY` encrypt stored credentials):
back up that directory separately, in a private location.
