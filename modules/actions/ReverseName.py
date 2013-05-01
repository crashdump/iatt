#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket

def action(mac, ip):
    try:
        hostname, _, addrlist = socket.gethostbyaddr(ip)
    except:
        hostname = None
    return hostname

# vim: noai:ts=4:sw=4
