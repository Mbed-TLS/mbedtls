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
        success = run_demo(demo)
        if not success:
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

def main():
    success = run_all_demos()
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
