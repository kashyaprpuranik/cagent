"""
Gmail OAuth2 provider - uses XOAUTH2 for IMAP/SMTP authentication.
"""

import imaplib
import logging
import smtplib

from config import EmailAccount
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from .base import EmailProvider

logger = logging.getLogger(__name__)

GMAIL_TOKEN_URI = "https://oauth2.googleapis.com/token"
GMAIL_SCOPES = [
    "https://mail.google.com/",
]


def _build_xoauth2_string(user: str, access_token: str) -> str:
    """Build XOAUTH2 authentication string."""
    return f"user={user}\x01auth=Bearer {access_token}\x01\x01"


class GmailProvider(EmailProvider):
    def __init__(self, account: EmailAccount):
        super().__init__(account)
        self._access_token: str = ""
        self._credentials: Credentials | None = None

    def refresh_credentials(self) -> bool:
        """Refresh Gmail OAuth2 access token using refresh token."""
        try:
            self._credentials = Credentials(
                token=None,
                refresh_token=self.account.credential.refresh_token,
                token_uri=GMAIL_TOKEN_URI,
                client_id=self.account.credential.client_id,
                client_secret=self.account.credential.client_secret,
                scopes=GMAIL_SCOPES,
            )
            self._credentials.refresh(Request())
            self._access_token = self._credentials.token
            logger.info(f"Gmail OAuth2 token refreshed for {self.account.email}")
            return True
        except Exception as e:
            logger.error(f"Gmail OAuth2 refresh failed for {self.account.email}: {e}")
            return False

    def _ensure_token(self):
        """Ensure we have a valid access token."""
        if not self._access_token or (self._credentials and self._credentials.expired):
            if not self.refresh_credentials():
                raise RuntimeError(f"Failed to refresh Gmail credentials for {self.account.email}")

    def connect_imap(self) -> imaplib.IMAP4_SSL:
        """Connect to Gmail IMAP with XOAUTH2."""
        self._ensure_token()
        imap = imaplib.IMAP4_SSL(
            self.account.imap_server,
            self.account.imap_port,
        )
        auth_string = _build_xoauth2_string(self.account.email, self._access_token)
        imap.authenticate("XOAUTH2", lambda x: auth_string.encode())
        logger.debug(f"Gmail IMAP connected for {self.account.email}")
        return imap

    def connect_smtp(self) -> smtplib.SMTP:
        """Connect to Gmail SMTP with XOAUTH2."""
        self._ensure_token()
        smtp = smtplib.SMTP(self.account.smtp_server, self.account.smtp_port)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        auth_string = _build_xoauth2_string(self.account.email, self._access_token)
        smtp.auth("XOAUTH2", lambda: auth_string)
        logger.debug(f"Gmail SMTP connected for {self.account.email}")
        return smtp
