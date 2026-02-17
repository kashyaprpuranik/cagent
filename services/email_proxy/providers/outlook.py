"""
Microsoft 365 / Outlook OAuth2 provider - uses XOAUTH2 for IMAP/SMTP authentication.
"""

import imaplib
import smtplib
import logging

import msal

from config import EmailAccount
from .base import EmailProvider

logger = logging.getLogger(__name__)

M365_AUTHORITY = "https://login.microsoftonline.com/common"
M365_SCOPES = [
    "https://outlook.office365.com/IMAP.AccessAsUser.All",
    "https://outlook.office365.com/SMTP.Send",
]


def _build_xoauth2_string(user: str, access_token: str) -> str:
    """Build XOAUTH2 authentication string."""
    return f"user={user}\x01auth=Bearer {access_token}\x01\x01"


class OutlookProvider(EmailProvider):
    def __init__(self, account: EmailAccount):
        super().__init__(account)
        self._access_token: str = ""
        self._msal_app: msal.ConfidentialClientApplication | None = None

    def _get_msal_app(self) -> msal.ConfidentialClientApplication:
        if self._msal_app is None:
            self._msal_app = msal.ConfidentialClientApplication(
                client_id=self.account.credential.client_id,
                client_credential=self.account.credential.client_secret,
                authority=M365_AUTHORITY,
            )
        return self._msal_app

    def refresh_credentials(self) -> bool:
        """Refresh M365 OAuth2 access token using refresh token."""
        try:
            app = self._get_msal_app()
            result = app.acquire_token_by_refresh_token(
                refresh_token=self.account.credential.refresh_token,
                scopes=M365_SCOPES,
            )
            if "access_token" in result:
                self._access_token = result["access_token"]
                logger.info(f"M365 OAuth2 token refreshed for {self.account.email}")
                return True
            else:
                logger.error(f"M365 OAuth2 refresh failed: {result.get('error_description', 'unknown error')}")
                return False
        except Exception as e:
            logger.error(f"M365 OAuth2 refresh failed for {self.account.email}: {e}")
            return False

    def _ensure_token(self):
        """Ensure we have a valid access token."""
        if not self._access_token:
            if not self.refresh_credentials():
                raise RuntimeError(f"Failed to refresh M365 credentials for {self.account.email}")

    def connect_imap(self) -> imaplib.IMAP4_SSL:
        """Connect to Outlook IMAP with XOAUTH2."""
        self._ensure_token()
        imap = imaplib.IMAP4_SSL(
            self.account.imap_server,
            self.account.imap_port,
        )
        auth_string = _build_xoauth2_string(self.account.email, self._access_token)
        imap.authenticate("XOAUTH2", lambda x: auth_string.encode())
        logger.debug(f"Outlook IMAP connected for {self.account.email}")
        return imap

    def connect_smtp(self) -> smtplib.SMTP:
        """Connect to Outlook SMTP with XOAUTH2."""
        self._ensure_token()
        smtp = smtplib.SMTP(self.account.smtp_server, self.account.smtp_port)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        auth_string = _build_xoauth2_string(self.account.email, self._access_token)
        smtp.auth("XOAUTH2", lambda: auth_string)
        logger.debug(f"Outlook SMTP connected for {self.account.email}")
        return smtp
