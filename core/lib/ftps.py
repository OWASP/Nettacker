import ftplib

from nettacker.core.lib.ftp import FtpEngine, FtpLibrary


class FtpsLibrary(FtpLibrary):
    client = ftplib.FTP_TLS


class FtpsEngine(FtpEngine):
    library = FtpsLibrary
