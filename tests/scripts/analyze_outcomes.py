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

def analyze_coverage(results, outcomes):
    """Check that all available test cases are executed at least once."""
    available = check_test_cases.collect_available_test_cases()
    for key in available:
        hits = outcomes[key].hits() if key in outcomes else 0
        if hits == 0:
            # Make this a warning, not an error, as long as we haven't
            # fixed this branch to have full coverage of test cases.
            results.warning('Test case not executed: {}', key)

def analyze_driver_vs_reference(outcomes, component_ref, component_driver, ignored_tests):
    """Check that all tests executed in the reference component are also
    executed in the corresponding driver component.
    Skip test suites provided in ignored_tests list.
    """
    available = check_test_cases.collect_available_test_cases()
    result = True

    for key in available:
        # Skip ignored test suites
        test_suite = key.split(';')[0] # retrieve test suit name
        test_suite = test_suite.split('.')[0] # retrieve main part of test suit name
        if test_suite in ignored_tests:
            continue
        # Continue if test was not executed by any component
        hits = outcomes[key].hits() if key in outcomes else 0
        if hits == 0:
            continue
        # Search for tests that run in reference component and not in driver component
        driver_test_passed = False
        reference_test_passed = False
        for entry in outcomes[key].successes:
            if component_driver in entry:
                driver_test_passed = True
            if component_ref in entry:
                reference_test_passed = True
        if(driver_test_passed is False and reference_test_passed is True):
            print('{}: driver: skipped/failed; reference: passed'.format(key))
            result = False
    return result

def analyze_outcomes(outcomes):
    """Run all analyses on the given outcome collection."""
    results = Results()
    analyze_coverage(results, outcomes)
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
    del args # unused
    outcomes = read_outcome_file(outcome_file)
    results = analyze_outcomes(outcomes)
    return results.error_count == 0

def do_analyze_driver_vs_reference(outcome_file, args):
    """Perform driver vs reference analyze."""
    ignored_tests = ['test_suite_' + x for x in args['ignored_suites']]

    outcomes = read_outcome_file(outcome_file)
    return analyze_driver_vs_reference(outcomes, args['component_ref'],
                                       args['component_driver'], ignored_tests)

# List of tasks with a function that can handle this task and additional arguments if required
TASKS = {
    'analyze_coverage':                 {
        'test_function': do_analyze_coverage,
        'args': {}},
    'analyze_driver_vs_reference_hash': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_hash_use_psa',
            'component_driver': 'test_psa_crypto_config_accel_hash_use_psa',
            'ignored_suites': ['shax', 'mdx', # the software implementations that are being excluded
                               'md',  # the legacy abstraction layer that's being excluded
                              ]}}
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
        options = parser.parse_args()

        if options.list:
            for task in TASKS:
                print(task)
            sys.exit(0)

        result = True

        if options.task == 'all':
            tasks = TASKS.keys()
        else:
            tasks = re.split(r'[, ]+', options.task)

            for task in tasks:
                if task not in TASKS:
                    print('Error: invalid task: {}'.format(task))
                    sys.exit(1)

        for task in TASKS:
            if task in tasks:
                if not TASKS[task]['test_function'](options.outcomes, TASKS[task]['args']):
                    result = False

        if result is False:
            sys.exit(1)
        print("SUCCESS :-)")
    except Exception: # pylint: disable=broad-except
        # Print the backtrace and exit explicitly with our chosen status.
        traceback.print_exc()
        sys.exit(120)

if __name__ == '__main__':
    main()
