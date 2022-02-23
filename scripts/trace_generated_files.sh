#!/bin/sh

set -eu

help () {
    cat <<EOF
Usage: $0 [OPTION]... REVISIONS [FILE]...
Log the values of the specified files for the specified Git revisions.

Run this script from a clean Git worktree.
This script runs \`make FILE\` to generate the desired files.
The outputs are stored in a subdirectory named for each commit hash.
REVISIONS is a comma-separated of Git revisions (see gitrevisions(7)).

Options:
  -U        Run even if the worktree is not clean
  -b DIR    Directory where to run \`make\` (default: .)
  -o DIR    Directory where the outputs will be stored (default: .)
  -r CMD    Shell command to run before each build
EOF
}

if [ $# -eq 0 ] || [ "$1" = "--help" ]; then
    help
    exit
fi


force_unclean=
build_dir=.
output_root=.
pre_command=

while getopts : OPTLET; do
    case $OPTLET in
        U) force_unclean=1;;
        b) build_dir=$OPTARG;;
        o) output_root=$OPTARG;;
        r) pre_command=$OPTARG;;
        \?) exit 120;;
    esac
done
shift $((OPTIND - 1))
all_revisions=$1

## trace_revision REVISION [FILE]...
trace_revision () {
    git checkout "$1"
    shift
    (cd -- "$output_root" && exec make -C  "$@")
    for file
    do
        mkdir -p -- "$output_root/$file"
        cp -p -- "$build_dir/$file" "$output_root/$file"
    done
}

## trace_revisions REVISION_RANGE [FILE]...
trace_revisions () {
    revisions=$(git log --format=%H "$1")
    shift
    for revision in $revisions; do
        trace_revision "$revision" "$@"
    done
}

if [ -z "$force_unclean" ]; then
    if ! git diff -q; then
        echo >&2 "$0: You have uncommitted changes. Please stash or commit them."
        exit 3
    fi
fi

initial_revision=$(git rev-parse --abbrev-ref HEAD)

while case $all_revisions in *,*) true;; *) false;; esac do
    trace_revisions "${all_revisions%%,*}" "$@"
    all_revisions=${all_revisions#*,}
done
trace_revisions "$all_revisions" "$@"

git checkout $initial_revision
