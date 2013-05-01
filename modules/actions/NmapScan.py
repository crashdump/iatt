#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess

def action(mac, ip):
    try:
        nmapbin = '/usr/bin/nmap'
        nmapargs = ' -PN -n -sV -F -A %s' % ip
        nmapcmd = nmapbin + nmapargs
        nmapresult = nmapcmd + '\n' + subprocess.check_output(nmapcmd, shell=True)
    except:
        nmapresult = None
    return nmapresult

# vim: noai:ts=4:sw=4
