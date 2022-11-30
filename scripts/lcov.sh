#!/bin/sh

	rm -rf Coverage
	lcov --capture --initial --directory library -o files.info
	lcov --rc lcov_branch_coverage=1 --capture --directory library -o tests.info
	lcov --rc lcov_branch_coverage=1 --add-tracefile files.info --add-tracefile tests.info -o all.info
	lcov --rc lcov_branch_coverage=1 --remove all.info -o final.info '*.h'
	gendesc tests/Descriptions.txt -o descriptions
	genhtml --title "mbed TLS" --description-file descriptions --keep-descriptions --legend --branch-coverage -o Coverage final.info
	rm -f files.info tests.info all.info final.info descriptions
