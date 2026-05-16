import ftplib
from unittest.mock import MagicMock, patch

from nettacker.core.lib.ftp import FtpEngine, FtpLibrary
from nettacker.core.lib.ftps import FtpsEngine, FtpsLibrary


class TestFtpsEngine:
    def test_engine_has_correct_library(self):
        assert FtpsEngine.library == FtpsLibrary

    def test_engine_subclasses_ftp_engine(self):
        assert issubclass(FtpsEngine, FtpEngine)


class TestFtpsLibrary:
    def test_library_subclasses_ftp_library(self):
        assert issubclass(FtpsLibrary, FtpLibrary)

    def test_client_is_ftp_tls(self):
        assert FtpsLibrary.client is ftplib.FTP_TLS

    @patch.object(FtpsLibrary, "client")
    def test_brute_force_uses_ftp_tls_client(self, mock_ftp_tls_class):
        mock_connection = MagicMock(spec=ftplib.FTP_TLS)
        mock_ftp_tls_class.return_value = mock_connection

        lib = FtpsLibrary()
        lib.brute_force("10.0.0.1", 21, "user", "pass", timeout=30)

        mock_ftp_tls_class.assert_called_once_with(timeout=30)
