"""
Generic IMAP/SMTP provider - uses plain password authentication.
"""

import imaplib
import smtplib
import logging

from config import EmailAccount
from .base import EmailProvider

logger = logging.getLogger(__name__)


class GenericProvider(EmailProvider):
    def __init__(self, account: EmailAccount):
        super().__init__(account)

    def refresh_credentials(self) -> bool:
        """No-op for password auth - passwords don't expire via refresh."""
        return True

    def connect_imap(self) -> imaplib.IMAP4_SSL:
        """Connect to IMAP server with password LOGIN."""
        imap = imaplib.IMAP4_SSL(
            self.account.imap_server,
            self.account.imap_port,
        )
        imap.login(self.account.email, self.account.credential.password)
        logger.debug(f"Generic IMAP connected for {self.account.email}")
        return imap

    def connect_smtp(self) -> smtplib.SMTP:
        """Connect to SMTP server with STARTTLS and password LOGIN."""
        smtp = smtplib.SMTP(self.account.smtp_server, self.account.smtp_port)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(self.account.email, self.account.credential.password)
        logger.debug(f"Generic SMTP connected for {self.account.email}")
        return smtp
