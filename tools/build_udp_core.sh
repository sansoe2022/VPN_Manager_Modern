#!/bin/sh
# Reproducible, static Hysteria v1 server/client with the checked-in lifecycle patch.
set -eu
case "$(go env GOVERSION)" in go1.20.*) ;; *) echo 'Use Go 1.20.x for the pinned quic-go v0.34 source.' >&2; exit 1;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "${1:-dist/udp}"
out=$(CDPATH= cd -- "${1:-dist/udp}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl -fL --retry 3 https://codeload.github.com/apernet/hysteria/tar.gz/57c5164854d6cfe00bead730cce731da2babe406 -o "$work/source.tar.gz"
printf '%s  %s\n' 9b7961871ebbf5eaa8bbebbd79f08418a6920d004d72f22e4ba0184226b7d215 "$work/source.tar.gz" | sha256sum -c -
mkdir "$work/src"
tar -xzf "$work/source.tar.gz" --strip-components=1 -C "$work/src"
cd "$work/src"
patch -p1 < "$root/native/hysteria-v1-modern.patch"
export CGO_ENABLED=0 GOOS=linux
for arch in amd64 arm64; do
  GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags '-s -w -buildid= -X main.appVersion=v1.3.5-modern.1 -X main.appCommit=57c5164854d6cfe00bead730cce731da2babe406' -o "$out/hysteria-linux-$arch" ./app/cmd
done
cd "$out"
sha256sum hysteria-linux-amd64 hysteria-linux-arm64 > SHA256SUMS
