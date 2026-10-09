# Splitter

Simple WebApp for splitting bills among friends for trips, etc.

Written in Rust.

## Deployment

On a fresh Ubuntu VPS, with the domain's DNS A records (`@` and `www`) pointing to it
and your SSH key in `~/.ssh/authorized_keys`:

```sh
git clone <this repo> ~/splitter && cd ~/splitter
sudo deploy/setup-server.sh splitter.info   # hardening, firewall, Caddy (HTTPS), services
deploy/deploy.sh                            # build and (re)start the app
```

To update after pulling new code, just run `deploy/deploy.sh` again.

- The app listens on `127.0.0.1:3000` only; Caddy serves it over HTTPS.
- Database: `/var/lib/splitter/splitter.db`, backed up daily to `/var/lib/splitter/backups/`
  (kept 30 days). Copy them off the server now and then:
  `ssh ubuntu@splitter.info 'sudo tar -C /var/lib/splitter -cz backups' > splitter-backups.tgz`
- Logs: `journalctl -u splitter` and `journalctl -u caddy`.
