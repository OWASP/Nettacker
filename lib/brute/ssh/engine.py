#!/usr/bin/env python
import threading
import time
import paramiko
from core.alert import *


def login(user, passwd,target,port,timeout_sec):
    exit = 0
    flag = 1
    while 1:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=user, password=passwd, timeout=timeout_sec)
            flag = 0
            exit = 0
            break
        except:
            exit += 1
            if exit is 10:
                warn('ssh connection to %s:%s timeout, skipping %s:%s'%(target,port,user,passwd))
                return 1
            time.sleep(0.1)

    if flag is 0:
        info('user:' + user + ' pass:' + passwd + ' server:' + target + ' port:' + str(port) + ' found!')
        save = open('results.txt', 'a')
        save.write('ssh ---> ' + user + ':' + passwd + ' ---> ' + target + ':' + str(port) + '\n')
        save.close()
    else:
        pass
    return flag

def start(target,users,passwds,ports,timeout_sec,thread_number,num,total): # Main function
    threads = []
    max = thread_number
    total_req = len(users) * len(passwds)
    for port in ports:
        # test ssh
        trying = 0
        portflag = True
        exit = 0
        while 1:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username='',password='',timeout=timeout_sec)
                exit = 0
                break
            except paramiko.ssh_exception.AuthenticationException, ssherr:
                if 'Authentication failed.' in ssherr:
                    break
                else:
                    exit += 1
                    if exit is 3:
                        error(
                            'ssh connection to %s:%s failed, skipping whole step [process %s of %s]! going to next step' % (
                            target, port, str(num), str(total)))
                        portflag = False
                        break
                    time.sleep(0.1)
            except:
                exit += 1
                if exit is 3:
                    error(
                        'ssh connection to %s:%s failed, skipping whole step [process %s of %s]! going to next step' % (
                            target, port, str(num), str(total)))
                    portflag = False
                    break
                time.sleep(0.1)

        if portflag is True:
            for user in users:
                for passwd in passwds:
                    t = threading.Thread(target=login, args=(user, passwd,target,port,timeout_sec))
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