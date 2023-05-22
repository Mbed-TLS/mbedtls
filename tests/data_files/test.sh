rm -f $1 && make $1 && python display_pem.py $1 | tee a.log
cd ~/work/mbedtls/mbedtls/tests/data_files && python $OLDPWD/display_pem.py $1 >a.log
