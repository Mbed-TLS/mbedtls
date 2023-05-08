import sys
CERTIFICATE_TEST_TYPE={
    "test-ca2-expired.crt" : "expired",
    "test-int-ca-exp.crt" : "expired",
}

match sys.argv[1]:
    case _ if sys.argv[1] not in CERTIFICATE_TEST_TYPE:
        print("x")

    case _ if CERTIFICATE_TEST_TYPE[sys.argv[1]] == "expired":
        print("exp", sys.argv[1])
