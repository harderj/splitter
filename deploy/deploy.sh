#!/usr/bin/env bash
# Build Splitter from this checkout and (re)start it. Run on the server as the
# admin user, after deploy/setup-server.sh:
#
#   deploy/deploy.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null; then
	[[ -x "$HOME/.cargo/bin/cargo" ]] ||
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
	source "$HOME/.cargo/env"
fi

echo "==> Building"
cargo build --release --locked

echo "==> Installing"
sudo install -m 755 target/release/splitter /opt/splitter/splitter
sudo systemctl restart splitter

sleep 1
if systemctl is-active --quiet splitter && curl -fsS -o /dev/null http://127.0.0.1:3000/; then
	echo "Splitter is running."
else
	sudo journalctl -u splitter -n 30 --no-pager
	exit 1
fi
