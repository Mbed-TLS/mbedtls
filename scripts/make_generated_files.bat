@rem Generate automatically-generated configuration-independent source files
@rem and build scripts.
@rem Perl and Python 3 must be on the PATH.
perl scripts\generate_errors.pl || exit /b
type library\error.c
perl scripts\generate_query_config.pl || exit /b
perl scripts\generate_features.pl || exit /b
type library\version_features.c
perl scripts\generate_visualc_files.pl || exit /b
python scripts\generate_psa_constants.py || exit /b
python tests\scripts\generate_psa_tests.py || exit /b
