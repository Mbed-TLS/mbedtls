"""Auxiliary functions used for logging module.
"""

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

import logging
import sys

def configure_logger(
        logger: logging.Logger,
        logger_format="[%(levelname)s]: %(message)s"
    ) -> None:
    """
    Configure the logging.Logger instance so that:
        - Format is set to any logger_format.
            Default: "[%(levelname)s]: %(message)s"
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

    log_formatter = logging.Formatter(logger_format)

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
