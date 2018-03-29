Password List Generator
====================================

if you want to output the generated list in a file:

from lib.payload.password_list_generator.engine import generate
password_list = generate(filename = "word_filename.txt")

if you don't want to output the generated list in a file:

from lib.payload.password_generator.engine import generate
password_list = generate()
