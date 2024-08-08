#!/usr/bin/env python3

"""Analyze the test outcomes from a full CI run.

This script can also run on outcomes from a partial run, but the results are
less likely to be useful.
"""

import argparse
import sys
import traceback
import re

import check_test_cases

class Results:
    """Process analysis results."""

    def __init__(self):
        self.error_count = 0
        self.warning_count = 0

    @staticmethod
    def log(fmt, *args, **kwargs):
        sys.stderr.write((fmt + '\n').format(*args, **kwargs))

    def error(self, fmt, *args, **kwargs):
        self.log('Error: ' + fmt, *args, **kwargs)
        self.error_count += 1

    def warning(self, fmt, *args, **kwargs):
        self.log('Warning: ' + fmt, *args, **kwargs)
        self.warning_count += 1

class TestCaseOutcomes:
    """The outcomes of one test case across many configurations."""
    # pylint: disable=too-few-public-methods

    def __init__(self):
        # Collect a list of witnesses of the test case succeeding or failing.
        # Currently we don't do anything with witnesses except count them.
        # The format of a witness is determined by the read_outcome_file
        # function; it's the platform and configuration joined by ';'.
        self.successes = []
        self.failures = []

    def hits(self):
        """Return the number of times a test case has been run.

        This includes passes and failures, but not skips.
        """
        return len(self.successes) + len(self.failures)

def analyze_coverage(results, outcomes, allow_list, full_coverage):
    """Check that all available test cases are executed at least once."""
    available = check_test_cases.collect_available_test_cases()
    for key in available:
        hits = outcomes[key].hits() if key in outcomes else 0
        if hits == 0 and key not in allow_list:
            if full_coverage:
                results.error('Test case not executed: {}', key)
            else:
                results.warning('Test case not executed: {}', key)
        elif hits != 0 and key in allow_list:
            # Test Case should be removed from the allow list.
            if full_coverage:
                results.error('Allow listed test case was executed: {}', key)
            else:
                results.warning('Allow listed test case was executed: {}', key)

def analyze_outcomes(outcomes, args):
    """Run all analyses on the given outcome collection."""
    results = Results()
    analyze_coverage(results, outcomes, args['allow_list'],
                     args['full_coverage'])
    return results

def read_outcome_file(outcome_file):
    """Parse an outcome file and return an outcome collection.

An outcome collection is a dictionary mapping keys to TestCaseOutcomes objects.
The keys are the test suite name and the test case description, separated
by a semicolon.
"""
    outcomes = {}
    with open(outcome_file, 'r', encoding='utf-8') as input_file:
        for line in input_file:
            (platform, config, suite, case, result, _cause) = line.split(';')
            key = ';'.join([suite, case])
            setup = ';'.join([platform, config])
            if key not in outcomes:
                outcomes[key] = TestCaseOutcomes()
            if result == 'PASS':
                outcomes[key].successes.append(setup)
            elif result == 'FAIL':
                outcomes[key].failures.append(setup)
    return outcomes

def do_analyze_coverage(outcome_file, args):
    """Perform coverage analysis."""
    outcomes = read_outcome_file(outcome_file)
    Results.log("\n*** Analyze coverage ***\n")
    results = analyze_outcomes(outcomes, args)
    return results.error_count == 0

# List of tasks with a function that can handle this task and additional arguments if required
TASKS = {
    'analyze_coverage':                 {
        'test_function': do_analyze_coverage,
        'args': {
            'allow_list': [
                # Algorithm not supported yet
                'test_suite_psa_crypto_metadata;Asymmetric signature: pure EdDSA',
                # Algorithm not supported yet
                'test_suite_psa_crypto_metadata;Cipher: XTS',
                # compat.sh tests with OpenSSL, DTLS 1.2 and singled-DES:
                # we have no version of OpenSSL on the CI that supports both
                # DTLS 1.2 and single-DES (1.0.2g is too recent for single-DES
                # and 1.0.1j is too old for DTLS 1.2).
                'compat;O->m dtls12,no DES-CBC-SHA',
                'compat;O->m dtls12,no EDH-RSA-DES-CBC-SHA',
                'compat;O->m dtls12,yes DES-CBC-SHA',
                'compat;O->m dtls12,yes EDH-RSA-DES-CBC-SHA',
                'compat;m->O dtls12,no TLS-DHE-RSA-WITH-DES-CBC-SHA',
                'compat;m->O dtls12,no TLS-RSA-WITH-DES-CBC-SHA',
                'compat;m->O dtls12,yes TLS-DHE-RSA-WITH-DES-CBC-SHA',
                'compat;m->O dtls12,yes TLS-RSA-WITH-DES-CBC-SHA',
            ],
            'full_coverage': False,
        }
    },
}

def main():
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('outcomes', metavar='OUTCOMES.CSV',
                            help='Outcome file to analyze')
        parser.add_argument('task', default='all', nargs='?',
                            help='Analysis to be done. By default, run all tasks. '
                                 'With one or more TASK, run only those. '
                                 'TASK can be the name of a single task or '
                                 'comma/space-separated list of tasks. ')
        parser.add_argument('--list', action='store_true',
                            help='List all available tasks and exit.')
        parser.add_argument('--require-full-coverage', action='store_true',
                            dest='full_coverage', help="Require all available "
                            "test cases to be executed and issue an error "
                            "otherwise. This flag is ignored if 'task' is "
                            "neither 'all' nor 'analyze_coverage'")
        options = parser.parse_args()

        if options.list:
            for task in TASKS:
                Results.log(task)
            sys.exit(0)

        result = True

        if options.task == 'all':
            tasks = TASKS.keys()
        else:
            tasks = re.split(r'[, ]+', options.task)

            for task in tasks:
                if task not in TASKS:
                    Results.log('Error: invalid task: {}'.format(task))
                    sys.exit(1)

        TASKS['analyze_coverage']['args']['full_coverage'] = \
            options.full_coverage

        for task in TASKS:
            if task in tasks:
                if not TASKS[task]['test_function'](options.outcomes, TASKS[task]['args']):
                    result = False

        if result is False:
            sys.exit(1)
        Results.log("SUCCESS :-)")
    except Exception: # pylint: disable=broad-except
        # Print the backtrace and exit explicitly with our chosen status.
        traceback.print_exc()
        sys.exit(120)

if __name__ == '__main__':
    main()
