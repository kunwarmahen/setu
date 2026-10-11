"""The profile lock Setu shares with Yantra, and Chrome's leftovers."""

import fcntl
import os
import socket

import pytest
from setu import profile_lock
from setu.browser import BrowserSignInFailed


def test_a_chrome_lock_from_another_computer_name_is_cleared(tmp_path, capsys):
    (tmp_path / "SingletonLock").symlink_to("LINUX-BOX-1702273")
    (tmp_path / "SingletonCookie").symlink_to("123")
    (tmp_path / "SingletonSocket").symlink_to(str(tmp_path / "gone" / "sock"))
    with profile_lock.held(tmp_path, wait=0):
        assert not any(tmp_path.glob("Singleton*"))
    assert "LINUX-BOX pid 1702273" in capsys.readouterr().err


def test_a_chrome_lock_of_this_computer_is_left_to_chrome(tmp_path):
    (tmp_path / "SingletonLock").symlink_to(f"{socket.gethostname()}-1")
    with profile_lock.held(tmp_path, wait=0):
        assert (tmp_path / "SingletonLock").is_symlink()


def test_a_chrome_that_answers_is_left_alone(tmp_path):
    path = tmp_path / "s"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as live:
        live.bind(str(path))
        live.listen(1)
        (tmp_path / "SingletonLock").symlink_to("LINUX-BOX-5")
        (tmp_path / "SingletonSocket").symlink_to(str(path))
        assert profile_lock.clear_left_chrome_lock(tmp_path) is None
    assert (tmp_path / "SingletonLock").is_symlink()


def test_a_yantra_on_the_profile_is_named_and_refused(tmp_path):
    (tmp_path / profile_lock.LOCK_NAME).write_text("42\n08:00\na schedule\n")
    fd = os.open(tmp_path / profile_lock.LOCK_NAME, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(BrowserSignInFailed, match=r"Yantra, for a schedule \(pid 42"):
            with profile_lock.held(tmp_path, wait=0):
                pass
    finally:
        os.close(fd)


def test_released_after_the_window(tmp_path):
    with profile_lock.held(tmp_path, wait=0):
        pass
    with profile_lock.held(tmp_path, wait=0):
        pass
