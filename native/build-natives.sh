#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
#
# Builds the tree-sitter core and grammar shared libraries (SPEC.md 15.3).
#
#   native/build-natives.sh fetch    download, verify and unpack the pinned sources into native/vendor/
#   native/build-natives.sh [build]  compile into target/native/<platform>/ (default: linux-x86_64)
#   native/build-natives.sh ensure   build only if the libraries for the platform are missing
#
# Environment: CC (default gcc), PLATFORM (default: detected), OUT (default: target/native/$PLATFORM).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VENDOR="$HERE/vendor"
LOCK="$HERE/sources.lock"

detect_platform() {
  local os arch
  case "$(uname -s)" in
    Linux) os=linux ;; Darwin) os=darwin ;; MINGW*|MSYS*|CYGWIN*) os=windows ;; *) os=unknown ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) arch=unknown ;;
  esac
  echo "$os-$arch"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/ciphersift-fetch.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  grep -v '^\s*#' "$LOCK" | grep -v '^\s*$' | while read -r dir tag sum url; do
    echo "fetch $dir $tag"
    curl -fsSL -o "$tmp/$dir.tar.gz" "$url"
    local got
    got="$(sha256 "$tmp/$dir.tar.gz")"
    if [ "$got" != "$sum" ]; then
      echo "build-natives: checksum mismatch for $url: expected $sum, got $got" >&2
      exit 1
    fi
    mkdir -p "$tmp/$dir"
    tar -xzf "$tmp/$dir.tar.gz" -C "$tmp/$dir" --strip-components=1
    rm -rf "${VENDOR:?}/$dir"
    mkdir -p "$VENDOR/$dir"
    if [ "$dir" = tree-sitter ]; then
      mkdir -p "$VENDOR/$dir/lib"
      cp -R "$tmp/$dir/lib/include" "$tmp/$dir/lib/src" "$VENDOR/$dir/lib/"
    else
      cp -R "$tmp/$dir/src" "$VENDOR/$dir/"
    fi
    cp "$tmp/$dir/LICENSE" "$VENDOR/$dir/LICENSE"
    echo "$tag" > "$VENDOR/$dir/TAG"
  done
}

build() {
  local platform="${PLATFORM:-$(detect_platform)}"
  local out="${OUT:-$ROOT/target/native/$platform}"
  local cc="${CC:-gcc}"
  local ext=so
  case "$platform" in darwin-*) ext=dylib ;; windows-*) ext=dll ;; esac
  for d in tree-sitter tree-sitter-java tree-sitter-python; do
    if [ ! -d "$VENDOR/$d" ]; then
      echo "build-natives: $VENDOR/$d missing; run '$0 fetch' first" >&2
      exit 1
    fi
  done
  mkdir -p "$out"
  local cflags="-O2 -fPIC -std=c11 -D_DEFAULT_SOURCE -fvisibility=default"
  echo "build $platform -> $out"
  "$cc" $cflags -I"$VENDOR/tree-sitter/lib/include" -I"$VENDOR/tree-sitter/lib/src" \
      -shared -o "$out/libtree-sitter.$ext" "$VENDOR/tree-sitter/lib/src/lib.c"
  for g in java python; do
    local srcs="$VENDOR/tree-sitter-$g/src/parser.c"
    [ -f "$VENDOR/tree-sitter-$g/src/scanner.c" ] && srcs="$srcs $VENDOR/tree-sitter-$g/src/scanner.c"
    # shellcheck disable=SC2086
    "$cc" $cflags -I"$VENDOR/tree-sitter-$g/src" -shared -o "$out/libtree-sitter-$g.$ext" $srcs
  done
  if [ "$ext" = so ] && command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "$out"/*.so
  fi
  ( cd "$out" && for f in libtree-sitter.$ext libtree-sitter-java.$ext libtree-sitter-python.$ext; do
      printf '%s  %s\n' "$(sha256 "$f")" "$f"; done > SHA256SUMS )
  cat "$out/SHA256SUMS"
}

ensure() {
  local platform="${PLATFORM:-$(detect_platform)}"
  local out="${OUT:-$ROOT/target/native/$platform}"
  if [ -f "$out/SHA256SUMS" ] && [ -n "$(ls "$out"/libtree-sitter* 2>/dev/null)" ] \
     && [ "$(wc -l < "$out/SHA256SUMS")" -ge 3 ]; then
    echo "native libraries for $platform present in $out"
  else
    build
  fi
}

case "${1:-build}" in
  fetch) fetch ;;
  ensure) ensure ;;
  build) build ;;
  all) fetch; build ;;
  *) echo "usage: $0 [fetch|build|ensure|all]" >&2; exit 2 ;;
esac
