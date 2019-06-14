#!/usr/bin/env python3
"""Run the Mbed TLS demo scripts.
"""
import glob
import subprocess
import sys

def run_demo(demo):
    """Run the specified demo script. Return True if it succeeds."""
    returncode = subprocess.call([demo])
    return returncode == 0

def run_demos(demos):
    """Run the specified demos and print summary information about failures.

    Return True if all demos passed and False if a demo fails.
    """
    failures = []
    for demo in demos:
        print('#### {} ####'.format(demo))
        if not run_demo(demo):
            failures.append(demo)
            print('{}: FAIL'.format(demo))
        print('')
    successes = len(demos) - len(failures)
    print('{}/{} demos passed'.format(successes, len(demos)))
    if failures:
        print('Failures:', *failures)
    return not failures

def run_all_demos():
    """Run all the available demos.

    Return True if all demos passed and False if a demo fails.
    """
    all_demos = glob.glob('programs/*/*_demo.sh')
    return run_demos(all_demos)

if __name__ == '__main__':
    if not run_all_demos():
        sys.exit(1)
