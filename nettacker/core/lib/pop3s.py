import poplib

from nettacker.core.lib.pop3 import Pop3Engine, Pop3Library


class Pop3sLibrary(Pop3Library):
    client = poplib.POP3_SSL


class Pop3sEngine(Pop3Engine):
    library = Pop3sLibrary
