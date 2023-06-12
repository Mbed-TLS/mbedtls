#!/usr/bin/env python3
"""
Set timestamp of files in current folder to git commit date
"""
import subprocess
import sys
import os
from multiprocessing.dummy import Pool


class SubProcessEnv:
    def __init__(self, cwd=None, text=True, stdout_only=True, raise_exception=False) -> None:
        self.cwd = cwd
        self.text = text
        self._stdout_only = stdout_only
        self._raise = raise_exception

    def __call__(self, cmd, input=None, stdout_only=None) -> str:
        if stdout_only is None:
            stdout_only = self._stdout_only
        completed_obj = subprocess.run(
            cmd, shell=True, cwd=self.cwd, capture_output=True, text=self.text, input=input)
        try:
            completed_obj.check_returncode()
        except subprocess.CalledProcessError as e:
            if self._raise:
                print(completed_obj.stderr.strip(), file=sys.stderr)
                raise
        if not stdout_only:
            return completed_obj.returncode, completed_obj.stdout.strip(), completed_obj.stderr.strip()
        return completed_obj.stdout.strip()


def set_file_timestamp_to_commit_time(filename):
    call = SubProcessEnv()
    string = call(f"git log -1 --format='%ct' {filename}")
    assert string
    mtime = float(string)
    atime = os.path.getatime(filename)
    os.utime(filename, times=(atime, mtime))
    return filename, mtime, atime


def main(args):
    call = SubProcessEnv()

    # Check if it is in a git worktree
    repo_root = call('git rev-parse --show-toplevel')
    cwd = os.path.abspath('.')
    repo_path = os.path.relpath(cwd, repo_root)
    files = []
    if args:
        files = ['--']
        files += args
    files = {os.path.join(repo_path, fname)
             for fname in call(f'git ls-files {" ".join(files)}').splitlines(keepends=False)}
    os.chdir(repo_root)

    dirty_files = {line.strip().split()[1]
                   for line in call(f'git status -s -- {" ".join(files)}').splitlines(keepends=False)}

    with Pool() as pool:
        for _ in pool.imap_unordered(set_file_timestamp_to_commit_time, files - dirty_files):
            pass


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
