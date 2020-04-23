## Common shell functions used by demo scripts programs/*/*.sh.

## How to write a demo script
## ==========================
##
## Include this file near the top of each demo script:
##   . "${0%/*}/../demo_common.sh"
##
## As the last thing in the script, call the cleanup function.
##
## You can use the functions and variables described below.

set -e -u

## $root_dir is the root directory of the Mbed TLS source tree.
root_dir="${0%/*}"
n=4 # limit the search depth
while ! [ -d "$root_dir/programs" ] || ! [ -d "$root_dir/library" ]; do
  if [ $n -eq 0 ]; then
    echo >&2 "This doesn't seem to be an Mbed TLS source tree."
    exit 125
  fi
  n=$((n - 1))
  case $root_dir in
    .) root_dir="..";;
    ..|?*/..) root_dir="$root_dir/..";;
    ?*/*) root_dir="${root_dir%/*}";;
    /*) root_dir="/";;
    *) root_dir=".";;
  esac
done

## $programs_dir is the directory containing the sample programs.
programs_dir="$root_dir/programs"

## msg LINE...
## msg <TEXT_ORIGIN
## Display an informational message.
msg () {
  if [ $# -eq 0 ]; then
    sed 's/^/# /'
  else
    for x in "$@"; do
      echo "# $x"
    done
  fi
}

## run "Message" COMMAND ARGUMENT...
## Display the message, then run COMMAND with the specified arguments.
run () {
    echo
    echo "# $1"
    shift
    echo "+ $*"
    "$@"
}

## Like '!', but stop on failure with 'set -e'
not () {
  if "$@"; then false; fi
}

## run_bad "Message" COMMAND ARGUMENT...
## Like run, but the command is expected to fail.
run_bad () {
  echo
  echo "$1 This must fail."
  shift
  echo "+ ! $*"
  not "$@"
}

## config_has SYMBOL...
## Succeeds if the library configuration has all SYMBOLs set.
config_has () {
  for x in "$@"; do
    "$programs_dir/test/query_compile_time_config" "$x"
  done
}

## Add the names of files to clean up to this whitespace-separated variable.
## The file names must not contain whitespace characters.
files_to_clean=



################################################################
## End of the public interfaces. Code beyond this point is not
## meant to be called directly from a demo script.

cleanup () {
  rm -f -- $files_to_clean
}
trap 'cleanup; trap - HUP; kill -HUP $$' HUP
trap 'cleanup; trap - INT; kill -INT $$' INT
trap 'cleanup; trap - TERM; kill -TERM $$' TERM

if config_has MBEDTLS_ENTROPY_NV_SEED; then
  # Create a seedfile that's sufficiently long in all library configurations.
  # This is necessary for programs that use randomness.
  # Assume that the name of the seedfile is the default name.
  files_to_clean="$files_to_clean seedfile"
  dd if=/dev/urandom of=seedfile ibs=64 obs=64 count=1
fi
