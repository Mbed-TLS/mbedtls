#!/bin/sh

set -eu

TREE=..

# default values, can be overriden by the environment
: ${DEST:=module}
: ${BUILD:=1}

# make sure we're running in our own directory
if [ -f create-module.sh ]; then :; else
    cd $( dirname $0 )
    if [ -f create-module.sh ]; then :; else
        echo "Please run the script from is directory." >&2
        exit 1
    fi
fi

# use a temporary directory to build the module, then rsync to DEST
# this allows touching only new files, for more efficient re-builds
TMP=$DEST-tmp
rm -rf $TMP

mkdir -p $TMP/mbedtls $TMP/source
cp $TREE/include/mbedtls/*.h $TMP/mbedtls
cp $TREE/library/*.c $TMP/source

# temporary, should depend on external module later
cp data/entropy_hardware_poll.c $TMP/source
cp data/target_config.h $TMP/mbedtls

data/adjust-config.sh $TREE/scripts/config.pl $TMP/mbedtls/config.h

mkdir -p $TMP/test
cp -r data/example-* $TMP/test
# later we should have the generated test suites here too

cp data/module.json $TMP
cp data/README.md $TMP

mkdir -p $DEST
rsync -cr --delete --exclude build --exclude yotta_\* $TMP/ $DEST/
rm -rf $TMP

echo "mbed TLS yotta module created in '$DEST'."

test_build()
{
    TARGET=$1
    echo; echo "*** Doing a test build for $TARGET ***"
    ( cd $DEST && yt target $TARGET && yt build )
}

if [ $BUILD -eq 1 ]; then
    if uname -a | grep 'Linux.*x86' >/dev/null; then
        test_build x86-linux-native
    fi

    if uname -a | grep 'Darwin.*x86' >/dev/null; then
        test_build x86-osx-native
    fi

    # do that one last so that it remains the target
    test_build frdm-k64f-gcc
fi
