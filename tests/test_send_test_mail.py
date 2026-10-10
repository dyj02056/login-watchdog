# ============================================================================
# test_send_test_mail.py — scripts/management/send_test_mail.py (메일 설정 점검 스크립트, guide34-a)
# ============================================================================

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "management")
)

import config
from notify import mailer
import send_test_mail  # noqa: E402


def test_success_returns_zero_and_never_prints_the_password(monkeypatch, capsys):
    monkeypatch.setattr(config, "SMTP_PASSWORD", "super-secret-app-password")
    monkeypatch.setattr(mailer, "send_test_mail", lambda to: (mailer.SENT, None, ""))

    code = send_test_mail.run("me@gmail.com")

    out = capsys.readouterr().out
    assert code == 0 and "[OK]" in out
    assert "super-secret-app-password" not in out and "설정됨" in out


def test_auth_failure_returns_one_with_a_fix_hint(monkeypatch, capsys):
    monkeypatch.setattr(mailer, "send_test_mail", lambda to: (mailer.FAILED, mailer.FAIL_AUTH, "SMTP 인증 실패: 535"))

    code = send_test_mail.run("me@gmail.com")

    out = capsys.readouterr().out
    assert code == 1 and "AUTH" in out and "앱 비밀번호" in out


def test_connect_failure_hint_mentions_port_and_tls_options(monkeypatch, capsys):
    monkeypatch.setattr(mailer, "send_test_mail", lambda to: (mailer.FAILED, mailer.FAIL_CONNECT, "timeout"))

    assert send_test_mail.run("me@gmail.com") == 1

    out = capsys.readouterr().out
    assert "587" in out and "465" in out


def test_refused_recipient_returns_one(monkeypatch, capsys):
    monkeypatch.setattr(mailer, "send_test_mail", lambda to: (mailer.REFUSED, None, ""))

    assert send_test_mail.run("nobody@gmail.com") == 1
    assert "거부" in capsys.readouterr().out
