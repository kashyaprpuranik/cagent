"""Tests for email providers with mocked IMAP/SMTP."""

import sys
import os
import imaplib
import smtplib
from unittest.mock import MagicMock, patch, PropertyMock
from email.mime.text import MIMEText

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import EmailAccount, EmailCredential, EmailPolicy
from providers.gmail import GmailProvider, _build_xoauth2_string
from providers.outlook import OutlookProvider
from providers.generic import GenericProvider


def _make_account(provider="generic", **kwargs):
    """Helper to create a test EmailAccount."""
    defaults = {
        "name": "test-account",
        "provider": provider,
        "email": "test@example.com",
        "imap_server": "imap.example.com",
        "imap_port": 993,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "credential": EmailCredential(password="testpass"),
        "policy": EmailPolicy(),
    }
    defaults.update(kwargs)
    return EmailAccount(**defaults)


class TestXOAuth2Format:
    def test_gmail_xoauth2_format(self):
        """XOAUTH2 string has correct format."""
        auth_string = _build_xoauth2_string("user@gmail.com", "access-token-123")
        expected = "user=user@gmail.com\x01auth=Bearer access-token-123\x01\x01"
        assert auth_string == expected

    def test_outlook_xoauth2_format(self):
        """Outlook uses same XOAUTH2 format."""
        from providers.outlook import _build_xoauth2_string as outlook_xoauth2
        auth_string = outlook_xoauth2("user@outlook.com", "ms-token-456")
        expected = "user=user@outlook.com\x01auth=Bearer ms-token-456\x01\x01"
        assert auth_string == expected


class TestGenericProvider:
    def test_generic_login_imap(self):
        """Generic provider uses LOGIN for IMAP."""
        account = _make_account(provider="generic")
        provider = GenericProvider(account)

        with patch("providers.generic.imaplib.IMAP4_SSL") as mock_imap_cls:
            mock_imap = MagicMock()
            mock_imap_cls.return_value = mock_imap

            result = provider.connect_imap()

            mock_imap_cls.assert_called_once_with("imap.example.com", 993)
            mock_imap.login.assert_called_once_with("test@example.com", "testpass")
            assert result is mock_imap

    def test_generic_login_smtp(self):
        """Generic provider uses STARTTLS + LOGIN for SMTP."""
        account = _make_account(provider="generic")
        provider = GenericProvider(account)

        with patch("providers.generic.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value = mock_smtp

            result = provider.connect_smtp()

            mock_smtp_cls.assert_called_once_with("smtp.example.com", 587)
            mock_smtp.ehlo.assert_called()
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with("test@example.com", "testpass")
            assert result is mock_smtp


class TestSendBasic:
    def test_send_constructs_email(self):
        """Email is constructed and sent via SMTP."""
        account = _make_account()
        provider = GenericProvider(account)

        mock_smtp = MagicMock()
        with patch.object(provider, "connect_smtp", return_value=mock_smtp):
            message_id = provider.send(
                to=["recipient@example.com"],
                subject="Test Subject",
                body="Hello World",
            )

            # Should have called sendmail
            mock_smtp.sendmail.assert_called_once()
            call_args = mock_smtp.sendmail.call_args
            assert call_args[0][0] == "test@example.com"  # from
            assert call_args[0][1] == ["recipient@example.com"]  # to
            assert "Test Subject" in call_args[0][2]  # message contains subject
            assert "Hello World" in call_args[0][2]  # message contains body
            mock_smtp.quit.assert_called_once()
            assert message_id is not None

    def test_send_with_cc_and_bcc(self):
        """CC and BCC recipients are included."""
        account = _make_account()
        provider = GenericProvider(account)

        mock_smtp = MagicMock()
        with patch.object(provider, "connect_smtp", return_value=mock_smtp):
            provider.send(
                to=["to@example.com"],
                subject="Test",
                body="body",
                cc=["cc@example.com"],
                bcc=["bcc@example.com"],
            )

            call_args = mock_smtp.sendmail.call_args
            all_recipients = call_args[0][1]
            assert "to@example.com" in all_recipients
            assert "cc@example.com" in all_recipients
            assert "bcc@example.com" in all_recipients


class TestInboxList:
    def test_inbox_list_basic(self):
        """IMAP SEARCH + FETCH returns message summaries."""
        account = _make_account()
        provider = GenericProvider(account)

        mock_imap = MagicMock()
        mock_imap.select.return_value = ("OK", [b"5"])
        mock_imap.search.return_value = ("OK", [b"1 2 3"])

        # Build a minimal email header
        header = b"From: sender@example.com\r\nTo: test@example.com\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
        mock_imap.fetch.return_value = ("OK", [(b"1 (RFC822.HEADER {100}", header)])

        with patch.object(provider, "connect_imap", return_value=mock_imap):
            messages = provider.list_messages(folder="INBOX", limit=10)

            mock_imap.select.assert_called_once_with("INBOX", readonly=True)
            mock_imap.search.assert_called_once()
            assert len(messages) > 0
            assert messages[0]["from"] == "sender@example.com"
            assert messages[0]["subject"] == "Hello"


class TestPolicyBlocksSend:
    def test_disallowed_recipient_blocked(self):
        """Policy check catches disallowed recipients before sending."""
        from policy import check_recipients_allowed

        policy = EmailPolicy(allowed_recipients=["*@company.com"])
        disallowed = check_recipients_allowed(["hacker@evil.com"], policy)
        assert len(disallowed) == 1
        assert disallowed[0] == "hacker@evil.com"


class TestGmailProvider:
    def test_gmail_refresh_credentials(self):
        """Gmail refresh uses google-auth credentials."""
        account = _make_account(
            provider="gmail",
            credential=EmailCredential(
                client_id="client-id",
                client_secret="client-secret",
                refresh_token="refresh-token",
            ),
        )
        provider = GmailProvider(account)

        with patch("providers.gmail.Credentials") as mock_creds_cls:
            mock_creds = MagicMock()
            mock_creds.token = "new-access-token"
            mock_creds.expired = False
            mock_creds_cls.return_value = mock_creds

            with patch("providers.gmail.Request"):
                result = provider.refresh_credentials()

            assert result is True
            assert provider._access_token == "new-access-token"

    def test_gmail_connect_imap_uses_xoauth2(self):
        """Gmail IMAP uses XOAUTH2 authentication."""
        account = _make_account(
            provider="gmail",
            imap_server="imap.gmail.com",
            credential=EmailCredential(
                client_id="cid",
                client_secret="cs",
                refresh_token="rt",
            ),
        )
        provider = GmailProvider(account)
        provider._access_token = "test-token"
        # Prevent token refresh
        provider._credentials = MagicMock()
        provider._credentials.expired = False

        with patch("providers.gmail.imaplib.IMAP4_SSL") as mock_imap_cls:
            mock_imap = MagicMock()
            mock_imap_cls.return_value = mock_imap

            provider.connect_imap()

            mock_imap.authenticate.assert_called_once()
            auth_call = mock_imap.authenticate.call_args
            assert auth_call[0][0] == "XOAUTH2"
