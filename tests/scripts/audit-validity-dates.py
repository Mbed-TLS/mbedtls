#!/usr/bin/env python3
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Audit validity date of X509 crt/crl/csr.

This script is used to audit the validity date of crt/crl/csr used for testing.
It would print the information about X.509 data if the validity period of the
X.509 data didn't cover the provided validity period. The data are collected
from tests/data_files/ and tests/suites/*.data files by default.
"""

import os
import sys
import re
import typing
import argparse
import datetime
import glob
import logging
from enum import Enum

# The script requires cryptography >= 35.0.0 which is only available
# for Python >= 3.6. Disable the pylint error here until we were
# using modern system on our CI.
from cryptography import x509 #pylint: disable=import-error

from generate_test_code import FileWrapper

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import build_tree

class DataType(Enum):
    CRT = 1 # Certificate
    CRL = 2 # Certificate Revocation List
    CSR = 3 # Certificate Signing Request


class DataFormat(Enum):
    PEM = 1 # Privacy-Enhanced Mail
    DER = 2 # Distinguished Encoding Rules


class AuditData:
    """Store data location, type and validity period of X.509 objects."""
    #pylint: disable=too-few-public-methods
    def __init__(self, data_type: DataType, x509_obj):
        self.data_type = data_type
        self.location = ""
        self.fill_validity_duration(x509_obj)

    def fill_validity_duration(self, x509_obj):
        """Read validity period from an X.509 object."""
        # Certificate expires after "not_valid_after"
        # Certificate is invalid before "not_valid_before"
        if self.data_type == DataType.CRT:
            self.not_valid_after = x509_obj.not_valid_after
            self.not_valid_before = x509_obj.not_valid_before
        # CertificateRevocationList expires after "next_update"
        # CertificateRevocationList is invalid before "last_update"
        elif self.data_type == DataType.CRL:
            self.not_valid_after = x509_obj.next_update
            self.not_valid_before = x509_obj.last_update
        # CertificateSigningRequest is always valid.
        elif self.data_type == DataType.CSR:
            self.not_valid_after = datetime.datetime.max
            self.not_valid_before = datetime.datetime.min
        else:
            raise ValueError("Unsupported file_type: {}".format(self.data_type))


class X509Parser:
    """A parser class to parse crt/crl/csr file or data in PEM/DER format."""
    PEM_REGEX = br'-{5}BEGIN (?P<type>.*?)-{5}\n(?P<data>.*?)-{5}END (?P=type)-{5}\n'
    PEM_TAG_REGEX = br'-{5}BEGIN (?P<type>.*?)-{5}\n'
    PEM_TAGS = {
        DataType.CRT: 'CERTIFICATE',
        DataType.CRL: 'X509 CRL',
        DataType.CSR: 'CERTIFICATE REQUEST'
    }

    def __init__(self,
                 backends:
                 typing.Dict[DataType,
                             typing.Dict[DataFormat,
                                         typing.Callable[[bytes], object]]]) \
    -> None:
        self.backends = backends
        self.__generate_parsers()

    def __generate_parser(self, data_type: DataType):
        """Parser generator for a specific DataType"""
        tag = self.PEM_TAGS[data_type]
        pem_loader = self.backends[data_type][DataFormat.PEM]
        der_loader = self.backends[data_type][DataFormat.DER]
        def wrapper(data: bytes):
            pem_type = X509Parser.pem_data_type(data)
            # It is in PEM format with target tag
            if pem_type == tag:
                return pem_loader(data)
            # It is in PEM format without target tag
            if pem_type:
                return None
            # It might be in DER format
            try:
                result = der_loader(data)
            except ValueError:
                result = None
            return result
        wrapper.__name__ = "{}.parser[{}]".format(type(self).__name__, tag)
        return wrapper

    def __generate_parsers(self):
        """Generate parsers for all support DataType"""
        self.parsers = {}
        for data_type, _ in self.PEM_TAGS.items():
            self.parsers[data_type] = self.__generate_parser(data_type)

    def __getitem__(self, item):
        return self.parsers[item]

    @staticmethod
    def pem_data_type(data: bytes) -> typing.Optional[str]:
        """Get the tag from the data in PEM format

        :param data: data to be checked in binary mode.
        :return: PEM tag or "" when no tag detected.
        """
        m = re.search(X509Parser.PEM_TAG_REGEX, data)
        if m is not None:
            return m.group('type').decode('UTF-8')
        else:
            return None

    @staticmethod
    def check_hex_string(hex_str: str) -> bool:
        """Check if the hex string is possibly DER data."""
        hex_len = len(hex_str)
        # At least 6 hex char for 3 bytes: Type + Length + Content
        if hex_len < 6:
            return False
        # Check if Type (1 byte) is SEQUENCE.
        if hex_str[0:2] != '30':
            return False
        # Check LENGTH (1 byte) value
        content_len = int(hex_str[2:4], base=16)
        consumed = 4
        if content_len in (128, 255):
            # Indefinite or Reserved
            return False
        elif content_len > 127:
            # Definite, Long
            length_len = (content_len - 128) * 2
            content_len = int(hex_str[consumed:consumed+length_len], base=16)
            consumed += length_len
        # Check LENGTH
        if hex_len != content_len * 2 + consumed:
            return False
        return True


class Auditor:
    """A base class for audit."""
    def __init__(self, logger):
        self.logger = logger
        self.default_files = [] # type: typing.List[str]
        # A list to store the parsed audit_data.
        self.audit_data = [] # type: typing.List[AuditData]
        self.parser = X509Parser({
            DataType.CRT: {
                DataFormat.PEM: x509.load_pem_x509_certificate,
                DataFormat.DER: x509.load_der_x509_certificate
            },
            DataType.CRL: {
                DataFormat.PEM: x509.load_pem_x509_crl,
                DataFormat.DER: x509.load_der_x509_crl
            },
            DataType.CSR: {
                DataFormat.PEM: x509.load_pem_x509_csr,
                DataFormat.DER: x509.load_der_x509_csr
            },
        })

    def parse_file(self, filename: str) -> typing.List[AuditData]:
        """
        Parse a list of AuditData from file.

        :param filename: name of the file to parse.
        :return list of AuditData parsed from the file.
        """
        with open(filename, 'rb') as f:
            data = f.read()
        result = self.parse_bytes(data)
        if result is not None:
            result.location = filename
            return [result]
        else:
            return []

    def parse_bytes(self, data: bytes):
        """Parse AuditData from bytes."""
        for data_type in list(DataType):
            try:
                result = self.parser[data_type](data)
            except ValueError as val_error:
                result = None
                self.logger.warning(val_error)
            if result is not None:
                audit_data = AuditData(data_type, result)
                return audit_data
        return None

    def walk_all(self, file_list: typing.Optional[typing.List[str]] = None):
        """
        Iterate over all the files in the list and get audit data.
        """
        if file_list is None:
            file_list = self.default_files
        for filename in file_list:
            data_list = self.parse_file(filename)
            self.audit_data.extend(data_list)

    @staticmethod
    def find_test_dir():
        """Get the relative path for the MbedTLS test directory."""
        return os.path.relpath(build_tree.guess_mbedtls_root() + '/tests')


class TestDataAuditor(Auditor):
    """Class for auditing files in tests/data_files/"""
    def __init__(self, verbose):
        super().__init__(verbose)
        self.default_files = self.collect_default_files()

    def collect_default_files(self):
        """Collect all files in tests/data_files/"""
        test_dir = self.find_test_dir()
        test_data_glob = os.path.join(test_dir, 'data_files/**')
        data_files = [f for f in glob.glob(test_data_glob, recursive=True)
                      if os.path.isfile(f)]
        return data_files


def parse_suite_data(data_f):
    """
    Parses .data file for test arguments that possiblly have a
    valid X.509 data. If you need a more precise parser, please
    use generate_test_code.parse_test_data instead.

    :param data_f: file object of the data file.
    :return: Generator that yields test function argument list.
    """
    for line in data_f:
        line = line.strip()
        # Skip comments
        if line.startswith('#'):
            continue

        # Check parameters line
        match = re.search(r'\A\w+(.*:)?\"', line)
        if match:
            # Read test vectors
            parts = re.split(r'(?<!\\):', line)
            parts = [x for x in parts if x]
            args = parts[1:]
            yield args


class SuiteDataAuditor(Auditor):
    """Class for auditing files in tests/suites/*.data"""
    def __init__(self, options):
        super().__init__(options)
        self.default_files = self.collect_default_files()

    def collect_default_files(self):
        """Collect all files in tests/suites/*.data"""
        test_dir = self.find_test_dir()
        suites_data_folder = os.path.join(test_dir, 'suites')
        data_files = glob.glob(os.path.join(suites_data_folder, '*.data'))
        return data_files

    def parse_file(self, filename: str):
        """
        Parse a list of AuditData from file.

        :param filename: name of the file to parse.
        :return list of AuditData parsed from the file.
        """
        audit_data_list = []
        data_f = FileWrapper(filename)
        for test_args in parse_suite_data(data_f):
            for idx, test_arg in enumerate(test_args):
                match = re.match(r'"(?P<data>[0-9a-fA-F]+)"', test_arg)
                if not match:
                    continue
                if not X509Parser.check_hex_string(match.group('data')):
                    continue
                audit_data = self.parse_bytes(bytes.fromhex(match.group('data')))
                if audit_data is None:
                    continue
                audit_data.location = "{}:{}:#{}".format(filename,
                                                         data_f.line_no,
                                                         idx + 1)
                audit_data_list.append(audit_data)

        return audit_data_list


def list_all(audit_data: AuditData):
    print("{}\t{}\t{}\t{}".format(
        audit_data.not_valid_before.isoformat(timespec='seconds'),
        audit_data.not_valid_after.isoformat(timespec='seconds'),
        audit_data.data_type.name,
        audit_data.location))


def configure_logger(logger: logging.Logger) -> None:
    """
    Configure the logging.Logger instance so that:
        - Format is set to "[%(levelname)s]: %(message)s".
        - loglevel >= WARNING are printed to stderr.
        - loglevel <  WARNING are printed to stdout.
    """
    class MaxLevelFilter(logging.Filter):
        # pylint: disable=too-few-public-methods
        def __init__(self, max_level, name=''):
            super().__init__(name)
            self.max_level = max_level

        def filter(self, record: logging.LogRecord) -> bool:
            return record.levelno <= self.max_level

    log_formatter = logging.Formatter("[%(levelname)s]: %(message)s")

    # set loglevel >= WARNING to be printed to stderr
    stderr_hdlr = logging.StreamHandler(sys.stderr)
    stderr_hdlr.setLevel(logging.WARNING)
    stderr_hdlr.setFormatter(log_formatter)

    # set loglevel <= INFO to be printed to stdout
    stdout_hdlr = logging.StreamHandler(sys.stdout)
    stdout_hdlr.addFilter(MaxLevelFilter(logging.INFO))
    stdout_hdlr.setFormatter(log_formatter)

    logger.addHandler(stderr_hdlr)
    logger.addHandler(stdout_hdlr)


def main():
    """
    Perform argument parsing.
    """
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('-a', '--all',
                        action='store_true',
                        help='list the information of all the files')
    parser.add_argument('-v', '--verbose',
                        action='store_true', dest='verbose',
                        help='show logs')
    parser.add_argument('--not-before', dest='not_before',
                        help=('not valid before this date (UTC, YYYY-MM-DD). '
                              'Default: today'),
                        metavar='DATE')
    parser.add_argument('--not-after', dest='not_after',
                        help=('not valid after this date (UTC, YYYY-MM-DD). '
                              'Default: not-before'),
                        metavar='DATE')
    parser.add_argument('--data-files', action='append', nargs='*',
                        help='data files to audit',
                        metavar='FILE')
    parser.add_argument('--suite-data-files', action='append', nargs='*',
                        help='suite data files to audit',
                        metavar='FILE')

    args = parser.parse_args()

    # start main routine
    # setup logger
    logger = logging.getLogger()
    configure_logger(logger)
    logger.setLevel(logging.DEBUG if args.verbose else logging.ERROR)

    td_auditor = TestDataAuditor(logger)
    sd_auditor = SuiteDataAuditor(logger)

    data_files = []
    suite_data_files = []
    if args.data_files is None and args.suite_data_files is None:
        data_files = td_auditor.default_files
        suite_data_files = sd_auditor.default_files
    else:
        if args.data_files is not None:
            data_files = [x for l in args.data_files for x in l]
        if args.suite_data_files is not None:
            suite_data_files = [x for l in args.suite_data_files for x in l]

    # validity period start date
    if args.not_before:
        not_before_date = datetime.datetime.fromisoformat(args.not_before)
    else:
        not_before_date = datetime.datetime.today()
    # validity period end date
    if args.not_after:
        not_after_date = datetime.datetime.fromisoformat(args.not_after)
    else:
        not_after_date = not_before_date

    # go through all the files
    td_auditor.walk_all(data_files)
    sd_auditor.walk_all(suite_data_files)
    audit_results = td_auditor.audit_data + sd_auditor.audit_data

    # we filter out the files whose validity duration covers the provided
    # duration.
    filter_func = lambda d: (not_before_date < d.not_valid_before) or \
                            (d.not_valid_after < not_after_date)

    if args.all:
        filter_func = None

    # filter and output the results
    for d in filter(filter_func, audit_results):
        list_all(d)

    logger.debug("Done!")

if __name__ == "__main__":
    main()
