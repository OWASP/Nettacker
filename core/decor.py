#!/usr/bin/env python
# -*- coding: utf-8 -*-

from inspect import getargspec
from lib.socks_resolver.engine import getaddrinfo


def socks_proxy(func):

    r"""
    A decorator for SOCKS PROXY.

    Usage :
    -------

    from core.decor import socks_proxy


    @socks_proxy
    def conn(targ, port, socks_proxy, timeout_sec):

        # Perform your code
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s

    """
    def inner_wrapper(*args, **kwargs):

        r"""

        flag : Determines whether 'socks_proxy' is in the arguments of the passed function.

               Example :
               ---------

                @socks_proxy
                def myFunc(socks_proxy, other_args):
                    .....

                -> This will give : flag = True

                @socks_proxy
                def myFunc(other_args):
                    ....

                -> This will give : flag = False

        socks_proxy_in_args : Determines whether the parameters are passed as args.

                Example :
                ---------

                @socks_proxy
                def myFunc(socks_proxy, other_args):
                    .....

                >> myFunc('socks://username:password@127.0.0.1', 20)

                -> This will give : socks_proxy_in_args = True and
                -> This will give : socks_proxy_in_kwargs = False

        socks_proxy_in_kwargs : Determines whether the parameters are passed as kwargs.

                Example :
                ---------

                @socks_proxy
                def myFunc(socks_proxy, other_args):
                    .....

                >> myFunc(socks_proxy='socks://username:password@127.0.0.1', other_args=20)

                -> This will give : socks_proxy_in_args = False and
                -> This will give : socks_proxy_in_kwargs = True

        i : Integer variable used to index the args.

        """

        flag = False
        socks_proxy_in_args = False
        socks_proxy_in_kwargs = False
        i = 0

        argspec = getargspec(func)
        arg_list = argspec[0]

        # Check if 'socks_proxy' is in the list of function arguments
        if 'socks_proxy' in arg_list:
            flag = True

        # If 'socks_proxy' is the list then calculate the position of the argument
        # Example : def myFunc(arg1, arg2, arg3) has :
        # arg1 -> position = 0, arg2 -> position = 1 & so on...
        if flag == True and len(args) > 0:
            for arg in arg_list:
                if arg != 'socks_proxy':
                    i = i + 1
                else:
                    try:
                        if args[i] is not None:
                            socks_proxy = args[i]
                            socks_proxy_in_args = True
                    except IndexError as ie:
                        print(ie)
                    break

        # Check if 'socks_proxy' is passed as kwargs
        if kwargs.get('socks_proxy') is not None:
            socks_proxy = kwargs.get('socks_proxy')
            socks_proxy_in_kwargs = True

        # Finally after ensuring the availability of 'socks_proxy' parameter and collecting its value
        if socks_proxy_in_args or socks_proxy_in_kwargs:

            # Execute the socks_proxy template code
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo()
        return func(*args, **kwargs)

    return inner_wrapper
