#!/bin/sh
set -eu

case "${1-}" in
  --help|-h)
    printf '%s\n' 'Usage: sh install.sh [--with-broker] [hostdesk install flags]' \
      'Installs a verified Linux release and a systemd user service.' \
      '--with-broker additionally installs the root broker through sudo.' \
      'HOSTDESK_VERSION selects a release tag; default: latest.'
    exit 0
    ;;
esac

# Downloads verified release bytes; all machine-specific state is generated locally.
[ "$(uname -s)" = Linux ] || { printf '%s\n' 'Hostdesk supports Linux only.' >&2; exit 1; }
[ "$(id -u)" != 0 ] || { printf '%s\n' 'Run this installer as the dashboard owner, not root.' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf '%s\n' 'This release supports Linux amd64 and arm64.' >&2; exit 1 ;;
esac
for cmd in curl sha256sum systemctl install mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || { printf 'Required command missing: %s\n' "$cmd" >&2; exit 1; }
done
with_broker=false
if [ "${1-}" = --with-broker ]; then with_broker=true; shift; fi
version=${HOSTDESK_VERSION-latest}
case "$version" in
  latest) base=https://github.com/astoreyai/hostdesk/releases/latest/download ;;
  v[0-9]*) base="https://github.com/astoreyai/hostdesk/releases/download/$version" ;;
  *) printf '%s\n' 'HOSTDESK_VERSION must be latest or a version tag beginning with v.' >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
name="hostdesk-linux-$arch"
curl --fail --location --proto '=https' --tlsv1.2 "$base/$name" --output "$work/$name"
curl --fail --location --proto '=https' --tlsv1.2 "$base/THIRD_PARTY_NOTICES.txt" --output "$work/THIRD_PARTY_NOTICES.txt"
curl --fail --location --proto '=https' --tlsv1.2 "$base/SHA256SUMS" --output "$work/SHA256SUMS"
(cd "$work" && sha256sum --check --ignore-missing SHA256SUMS)
install -d -m 0755 "$HOME/.local/bin"
install -m 0755 "$work/$name" "$HOME/.local/bin/hostdesk"
install -d -m 0755 "${XDG_DATA_HOME:-$HOME/.local/share}/hostdesk"
install -m 0644 "$work/THIRD_PARTY_NOTICES.txt" "${XDG_DATA_HOME:-$HOME/.local/share}/hostdesk/THIRD_PARTY_NOTICES.txt"
"$HOME/.local/bin/hostdesk" install "$@"
if [ "$with_broker" = true ]; then
  command -v sudo >/dev/null 2>&1 || { printf '%s\n' 'sudo is required for --with-broker.' >&2; exit 1; }
  sudo "$HOME/.local/bin/hostdesk" install-broker --uid "$(id -u)"
  "$HOME/.local/bin/hostdesk" init "$@" --broker-socket /run/hostdesk/broker.sock
  systemctl --user restart hostdesk.service
fi
printf '%s\n' 'Installed. Run ~/.local/bin/hostdesk address, then ~/.local/bin/hostdesk token.'
