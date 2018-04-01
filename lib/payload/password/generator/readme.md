Password List Generator
====================================

if you want to output the generated list in a file:

from lib.payload.password_list_generator.engine import generate
password_list = generate(filename = "myfilename.txt", first_name = "", last_name = "", nick= "", email = "", dob = "", phone = "", partner_name = "", partner_dob = "", bestfriend = "", child_name = "", company = "", other = "",  maxm = 8, minm = 16, special_characters = False, leet_speak = False, random_numbers = False, language="en")

if you don't want to output the generated list in a file:

from lib.payload.password_generator.engine import generate
password_list = generate(first_name="", last_name = "", nick= "", email = "", dob = "", phone = "", partner_name = "", partner_dob = "", bestfriend = "", child_name = "", company = "", other = "",  maxm = 8, minm = 16, special_characters = False, leet_speak = False, random_numbers = False, language="en")

dob = Date of Birth- Format (DD/MM/YYYY, Eg. 28/05/1996)

other = Add more characters to the password list seperated by , For Eg. "hello,world,my,name,is,pradeep"

minm = Minimum number of characters for the elements in password list (Default - 8)

maxm = Maximum number of characters for the elements in password list (Default - 16)

Special Character = Adding Special characters in the list
['@', '*', '!', '#', '$']

1337 Speak = 1337 mode can convert the characters to leet speak and hello = h3110 
[ a='@', t='7', l='1', e='3', i='!', o='0', z='2', g='9', s='5' ]

random numbers = Adding Random Numbers in the list
['98765', '9876', '987', '123', '1234', '12345']

