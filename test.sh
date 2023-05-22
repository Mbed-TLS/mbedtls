set -ex

test_x905_parser(){
    make clean
    make all -j20
    cd tests

    ./test_suite_x509parse 2>&1 > test1.log
    faketime -f '+4y' ./test_suite_x509parse 2>&1 >test.log
    cd ..
}

git checkout HEAD -- include/mbedtls/mbedtls_config.h
test_x905_parser

scripts/config.py full
test_x905_parser


