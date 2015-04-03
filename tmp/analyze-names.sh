#!/bin/sh

set -eu

tmp/list-macros.sh
tmp/list-enum-consts.pl
tmp/list-identifiers.sh
tmp/list-symbols.sh

UNDECLARED=$( diff exported-symbols identifiers | sed -n -e 's/^< //p' )
if [ "x$UNDECLARED" == "x" ]; then
    echo "All exported symbols are declared in headers: good"
else
    echo "The following symbols are probably missing a 'static': $UNDECLARED"
fi

for THING in macros identifiers enum-consts; do
    echo ''
    echo "=== $THING ==="

    NO_=$( grep -v _ $THING | tr '\n' ' ' )
    echo "Without underscore: $NO_"

    cut -f1 -d_ $THING | uniq -c | sort -nr > prefix-$THING
    echo "By prefix: (10 most frequent, see prefix-$THING for full list)"
    head -n 10 < prefix-$THING
done

echo ''; echo "=== all public names ==="
sort -u macros identifiers enum-consts > public-names
wc -l public-names


NL='
'
sed -n 's/POLARSSL_[A-Z0-9_]*/\'"$NL"'&\'"$NL"/gp \
    include/mbedtls/*.h tests/scripts/* scripts/* library/*.c configs/*.h \
    | grep POLARSSL | sort -u > _POLARSSL_XXX
diff public-names _POLARSSL_XXX | sed -n 's/^> //p' > extra-names
rm _POLARSSL_XXX

echo 'polarssl_zeroize' >> extra-names

wc -l extra-names

for THING in public-names extra-names; do
    if grep '[^A-Za-z0-9_]' $THING; then
        echo "invalid character in $THING" >&2
        exit 1;
    fi
done
