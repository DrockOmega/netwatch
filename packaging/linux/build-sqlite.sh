#!/usr/bin/env bash
# Builds the private SQLite the Linux sensor's venv preloads (install-sensor.sh): Ubuntu 26.04's 3.46.1 has the
# WAL-reset corruption bug fixed in 3.51.3. Output: ./libsqlite3.so.0
set -euo pipefail
V=3540000 YEAR=2026 SHA3=f5e3e724e9c9b3b5d512c76b02082091a59eeea9becd169a9fbf4d376403acce   # sqlite.org download page
work=$(mktemp -d "${TMPDIR:-$HOME/tmp}/sqlite.XXXXXX"); trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/src.tgz" "https://sqlite.org/$YEAR/sqlite-autoconf-$V.tar.gz"
[[ $(openssl dgst -sha3-256 "$work/src.tgz" | awk '{print $NF}') == "$SHA3" ]] || { echo "sqlite source hash mismatch" >&2; exit 1; }
tar -xzf "$work/src.tgz" -C "$work"
# Ubuntu's compile options, minus ENABLE_UPDATE_DELETE_LIMIT (needs a parser rebuild, not the amalgamation).
gcc -O2 -fPIC -shared -Wl,-soname,libsqlite3.so.0 -o libsqlite3.so.0 \
  -DSQLITE_THREADSAFE=1 -DSQLITE_SECURE_DELETE -DSQLITE_DEFAULT_AUTOVACUUM=1 -DSQLITE_DEFAULT_RECURSIVE_TRIGGERS=1 \
  -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=2 -DSQLITE_DIRECT_OVERFLOW_READ -DSQLITE_ALLOW_ROWID_IN_VIEW -DSQLITE_LIKE_DOESNT_MATCH_BLOBS \
  -DSQLITE_SOUNDEX -DSQLITE_USE_URI=1 -DSQLITE_TEMP_STORE=1 -DSQLITE_MAX_SCHEMA_RETRY=25 -DSQLITE_MAX_VARIABLE_NUMBER=250000 \
  -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_ENABLE_DBPAGE_VTAB -DSQLITE_ENABLE_DBSTAT_VTAB -DSQLITE_ENABLE_FTS3 \
  -DSQLITE_ENABLE_FTS3_PARENTHESIS -DSQLITE_ENABLE_FTS4 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_MATH_FUNCTIONS \
  -DSQLITE_ENABLE_PREUPDATE_HOOK -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_STMTVTAB -DSQLITE_ENABLE_UNLOCK_NOTIFY \
  "$work/sqlite-autoconf-$V/sqlite3.c" -lpthread -lm
LD_LIBRARY_PATH=. python3 -I -c 'import sqlite3; print("built", sqlite3.sqlite_version)'
