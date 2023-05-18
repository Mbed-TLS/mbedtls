set -ex
scripts/config.py full
make clean
make all -j20
cd tests

./test_suite_x509parse 2>&1 | tee test1.log 
faketime -f '+4y' ./test_suite_x509parse 2>&1 | tee test.log

