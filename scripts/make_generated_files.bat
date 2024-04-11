@rem Generate automatically-generated configuration-independent source files
@rem and build scripts.
@rem Perl and Python 3 must be on the PATH.
@rem psa_crypto_driver_wrappers.h needs to be generated prior to
@rem generate_visualc_files.pl being invoked.
python scripts\generate_driver_wrappers.py || exit /b 1
perl scripts\generate_errors.pl || exit /b 1
perl scripts\generate_query_config.pl || exit /b 1
perl scripts\generate_features.pl || exit /b 1
python scripts\generate_ssl_debug_helpers.py || exit /b 1
perl scripts\generate_visualc_files.pl || exit /b 1
python scripts\generate_psa_constants.py || exit /b 1
python tests\scripts\generate_bignum_tests.py || exit /b 1
python tests\scripts\generate_ecp_tests.py || exit /b 1
python tests\scripts\generate_psa_tests.py || exit /b 1
python tests\scripts\generate_test_keys.py --output tests\src\test_keys.h || exit /b 1
python tests\scripts\generate_test_cert_macros.py --output tests\src\test_certs.h ^
                --string TEST_CA_CRT_EC_PEM=tests\data_files\test-ca2.crt ^
                --binary TEST_CA_CRT_EC_DER=tests\data_files\test-ca2.crt.der ^
                --string TEST_CA_KEY_EC_PEM=tests\data_files\test-ca2.key.enc ^
                --password TEST_CA_PWD_EC_PEM=PolarSSLTest ^
                --binary TEST_CA_KEY_EC_DER=tests\data_files\test-ca2.key.der ^
                --string TEST_CA_CRT_RSA_SHA256_PEM=tests\data_files\test-ca-sha256.crt ^
                --binary TEST_CA_CRT_RSA_SHA256_DER=tests\data_files\test-ca-sha256.crt.der ^
                --string TEST_CA_CRT_RSA_SHA1_PEM=tests\data_files\test-ca-sha1.crt ^
                --binary TEST_CA_CRT_RSA_SHA1_DER=tests\data_files\test-ca-sha1.crt.der ^
                --string TEST_CA_KEY_RSA_PEM=tests\data_files\test-ca.key ^
                --password TEST_CA_PWD_RSA_PEM=PolarSSLTest ^
                --binary TEST_CA_KEY_RSA_DER=tests\data_files\test-ca.key.der ^
                --string TEST_SRV_CRT_EC_PEM=tests\data_files\server5.crt ^
                --binary TEST_SRV_CRT_EC_DER=tests\data_files\server5.crt.der ^
                --string TEST_SRV_KEY_EC_PEM=tests\data_files\server5.key ^
                --binary TEST_SRV_KEY_EC_DER=tests\data_files\server5.key.der ^
                --string TEST_SRV_CRT_RSA_SHA256_PEM=tests\data_files\server2-sha256.crt ^
                --binary TEST_SRV_CRT_RSA_SHA256_DER=tests\data_files\server2-sha256.crt.der ^
                --string TEST_SRV_CRT_RSA_SHA1_PEM=tests\data_files\server2.crt ^
                --binary TEST_SRV_CRT_RSA_SHA1_DER=tests\data_files\server2.crt.der ^
                --string TEST_SRV_KEY_RSA_PEM=tests\data_files\server2.key ^
                --binary TEST_SRV_KEY_RSA_DER=tests\data_files\server2.key.der ^
                --string TEST_CLI_CRT_EC_PEM=tests\data_files\cli2.crt ^
                --binary TEST_CLI_CRT_EC_DER=tests\data_files\cli2.crt.der ^
                --string TEST_CLI_KEY_EC_PEM=tests\data_files\cli2.key ^
                --binary TEST_CLI_KEY_EC_DER=tests\data_files\cli2.key.der ^
                --string TEST_CLI_CRT_RSA_PEM=tests\data_files\cli-rsa-sha256.crt ^
                --binary TEST_CLI_CRT_RSA_DER=tests\data_files\cli-rsa-sha256.crt.der ^
                --string TEST_CLI_KEY_RSA_PEM=tests\data_files\cli-rsa.key ^
                --binary TEST_CLI_KEY_RSA_DER=tests\data_files\cli-rsa.key.der || exit /b 1
