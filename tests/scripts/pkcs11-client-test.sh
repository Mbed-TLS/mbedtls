#!/bin/sh
set -u -e

TOKEN_DIR=softhsm2.d

if [ -e library/aes.c ]; then
  TOPDIR="$PWD"
elif [ -e ../library/aes.c ]; then
  TOPDIR="${PWD%/*}"
elif [ -e ../../library/aes.c ]; then
  TOPDIR="${PWD%/*/*}"
elif [ -e ../../../library/aes.c ]; then
  TOPDIR="${PWD%/*/*/*}"
else
  unset TOPDIR
fi
if [ -n "${TOPDIR+1}" ] &&
     make -C "$TOPDIR/programs" util/syslog2stderr.so >/dev/null 2>&1
then
  case $(uname) in
    Darwin)
      export DYLD_PRELOAD="${DYLD_PRELOAD-}:$TOPDIR/programs/util/syslog2stderr.so";;
    *)
      export LD_PRELOAD="${LD_PRELOAD-}:$TOPDIR/programs/util/syslog2stderr.so";;
  esac
fi

# softhsm2_find_token LABEL
softhsm2_find_token () {
  softhsm2-util --show-slots | awk -v label="$1" '
    $1 == "Slot" && $2 ~ /^[0-9]+$/ {slot = $2}
    $1 == "Label:" && $2 == label {print slot; found=1; exit}
    END {exit(!found)}
  '
}

# softhsm2_create_token LABEL
softhsm2_create_token () {
  softhsm2_find_token "$1" || {
    softhsm2-util --init-token --free --so-pin 0000 --pin 0000 --label "$1" &&
    softhsm2_find_token "$1"
  }
}

softhsm2_init () {
  test -d "$TOKEN_DIR" || mkdir "$TOKEN_DIR"
  scratch_token=$(softhsm2_create_token "scratch")
}

case $1 in
  find_slot) softhsm2_find_token "$2";;
  init) softhsm2_init;;
  *) echo >&2 "$0: Unknown command: $1"; exit 120;;
esac
