#!/bin/bash

set -eu

GITIGNORES=$(find . -name ".gitignore")

for GITIGNORE in $GITIGNORES; do
    IN_GEN_BLOCK=false
    while read -r line; do
        if [ "$line" = "###START_GENERATED_FILES###" ]; then
            IN_GEN_BLOCK=true
            echo "###START_COMMENTED_GENERATED_FILES###"
        elif [ "$line" = "###END_GENERATED_FILES###" ]; then
            IN_GEN_BLOCK=false
            echo "###END_COMMENTED_GENERATED_FILES###"
        elif $IN_GEN_BLOCK ; then
            echo "#$line"
        else
            echo "$line"
        fi
    done <$GITIGNORE > "$GITIGNORE.tmp"
    mv "$GITIGNORE.tmp" $GITIGNORE
done
