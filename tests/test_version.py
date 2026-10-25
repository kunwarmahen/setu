"""The version: the day of the last commit, and that day's count.

The bias is A NUMBER NOBODY BUMPS THAT STILL SAYS SOMETHING TRUE. It is
worked out from the history, so the tests make real commits on chosen
days and check the count; an image with no git reads the VERSION file
``sarathi image`` writes; and a checkout with uncommitted changes says
so rather than passing for its last commit.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import pytest
from setu import version


def git(repo: Path, *args: str, when: str | None = None) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    if when:
        env |= {"GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=env).stdout.strip()


def commit(repo: Path, words: str, when: str) -> str:
    (repo / "kept.txt").write_text(words + "\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", words, when=when)
    return git(repo, "rev-parse", "--short", "HEAD")


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    return tmp_path


def test_the_third_commit_of_a_day_is_that_day_dot_three(repo):
    commit(repo, "one", "2026-10-24T22:00:00+05:30")
    commit(repo, "two", "2026-10-25T09:00:00+05:30")
    commit(repo, "three", "2026-10-25T10:00:00+05:30")
    last = commit(repo, "four", "2026-10-25T23:30:00+05:30")
    assert version.from_git(repo) == ("2026.10.25.3", last)


def test_the_day_is_the_one_the_commit_was_made_in(repo):
    # 23:30 in India is still the 25th there, though it is the 26th nowhere near
    last = commit(repo, "late", "2026-10-25T23:30:00+05:30")
    assert version.from_git(repo) == ("2026.10.25.1", last)


def test_uncommitted_changes_are_said(repo):
    commit(repo, "one", "2026-10-25T09:00:00+00:00")
    (repo / "kept.txt").write_text("edited\n")
    assert version.from_git(repo)[0] == "2026.10.25.1+dirty"


def test_an_image_with_no_git_reads_the_file_sarathi_wrote(tmp_path):
    assert version.from_git(tmp_path) is None
    (tmp_path / version.FILE).write_text("2026.10.25.3 a65654e\n")
    assert version.from_file(tmp_path) == ("2026.10.25.3", "a65654e")


def test_neither_is_the_packages_own_number(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "ROOT", tmp_path)
    version.found.cache_clear()
    try:
        number, at = version.found()
        assert at == "" and number == version.from_package()
        assert version.line() == number
    finally:
        version.found.cache_clear()


def test_version_prints_the_number_and_the_commit(monkeypatch, capsys):
    monkeypatch.setattr(version, "found", lambda: ("2026.10.25.3", "a65654e"))
    parser = argparse.ArgumentParser(prog="setu")
    parser.add_argument("--version", action=version.Show)
    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])
    assert capsys.readouterr().out == "setu 2026.10.25.3 (a65654e)\n"
