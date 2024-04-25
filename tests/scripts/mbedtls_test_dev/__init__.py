import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                              os.path.pardir,os.path.pardir, os.path.pardir,
                             'scripts'))
from mbedtls_dev import *