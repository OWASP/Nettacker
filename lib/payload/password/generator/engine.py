#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani
# Password List Generator tool
# https://github.com/pradeepjairamani/password_list_generator

import os
import sys
from core.log import __log_into_file
import json

# Declarations

global monthly
global list1

monthly = {"01": "jan", "02": "feb", "03": "march", "04": "april", "05": "may", "06": "june", "07": "july",
           "08": "aug", "09": "sept", "10": "oct", "11": "nov", "12": "dec"}

charlist = ['@', '*', '!', '#', '$']

random_list = ['98765', '9876', '987', '123', '1234', '12345']

password_list = list()
list1 = list()
characters_list = list()
leet_list = list()
unique_list = list()
random_l = list()


def datepart(date):
    if(len(date) != 0):
        date, sep, tail = date.partition("/")
        month, sep, year = tail.partition("/")
        list1.append(date)
        list1.append(month)
        list1.append(year)
        try:
            list1.append(monthly[month])
        except:
            print("Month not entered Correctly")
        list1.append(date[::-1])
        list1.append(month[::-1])
        list1.append(year[::-1])
        list1.append(year[2:])
        list1.append(year[1:])


def generate(filename = "", first_name="", last_name = "", nick= "", email = "", dob = "", phone = "", partner_name = "", partner_dob = "", bestfriend = "", child_name = "", company = "", other = "",  maxm = 8, minm = 16, special_characters = False, leet_speak = False, random_numbers = False, language="en"):
    random_l=list()
    other = other.replace(" ", "")
    words2 = other.split(",")
    if special_characters == True:
        special = list()
        for spec1 in charlist:
            special.append(spec1)
            for spec2 in charlist:
                special.append(spec1 + spec2)
                for spec3 in charlist:
                    special.append(spec1 + spec2 + spec3)

    # 1337 mode can convert the characters to leet speak and hello = h3110
    ################################

    funame = first_name.title()
    nuick = nick.title()
    purtname = partner_name.title()
    bustf = bestfriend.title()
    chld = child_name.title()
    #chldn = childn.title()
    cumpny = company.title()

    # 3

    emails, sep, tail = email.partition("@")

    list1 = [first_name, last_name, nick, emails, funame, nuick, phone, partner_name,
            bestfriend, purtname, bustf, child_name, company, chld, cumpny]
    for i in words2:
        list1.append(i)

    datepart(partner_dob)
    # datepart(childob)
    datepart(dob)

    list1 = list(filter(None, list1))  # removing empty data

    for i in list1:
        password_list.append(i)
        for j in list1:
            if(i.lower()) != (j.lower()):
                password_list.append(i + j)

    if leet_speak == True:
        for i in password_list:
            i = i.replace('a', '@')
            i = i.replace('t', '7')
            i = i.replace('l', '1')
            i = i.replace('e', '3')
            i = i.replace('i', '!')
            i = i.replace('o', '0')
            i = i.replace('z', '2')
            i = i.replace('g', '9')
            i = i.replace('s', '5')
            leet_list.append(i)

    # Leet Speak chars
    # a='@'
    # t='7'
    # l='1'
    # e='3'
    # i='!'
    # o='0'
    # z='2'
    # g='9'
    # s='5'
    ####################

    if random_numbers == True:
        for i in password_list:
            for j in random_list:
                random_l.append(i + j)
    else:
        random_l = password_list

    if special_characters == True:
        for i in random_l:
            for j in special:
                characters_list.append(i + j)
    count = 0
    unique_list = password_list + random_l + characters_list + leet_list
    unique_list = list(set(tuple(unique_list)))
    for i in unique_list:
        if minm <= len(i) <= maxm:
            pass
        else:
            unique_list.remove(i)
    
    if filename is not "":
        __log_into_file(filename, 'w', json.dumps(unique_list), language, final=True)
    return unique_list
