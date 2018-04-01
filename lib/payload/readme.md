OWASP Nettacker Payloads
=====================================

OWASP Nettacker payloads are located in here

Password List Generator
====================================

if you want to output the generated list in a file:

from lib.payload.password_list_generator import generate
password_list = generate("word_filename.txt")

if you don't want to output the generated list in a file:

from lib.payload.password_list_generator import generate
password_list = generate(None)

