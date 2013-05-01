#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# ArpAction v0.2.0 (20130502)
__prog__='arpaction'
__version__='0.2.0'

#
# Depends on the python-scapy library: http://www.secdev.org/projects/scapy/
# Depends on the python-daemon library: https://pypi.python.org/pypi/python-daemon/
#

#
# Copyright (c) 2013, Adrien Pujol <adrien.pujol@crashdump.fr>
__author__ = "Adrien Pujol"
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies, 
# either expressed or implied, of the project.
#

# Standard libs
import sys, datetime, logging, time
from optparse import OptionParser
import cPickle

# Third party libs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from daemon import runner

#
# Add new module steps:
#  - Add the "from modules.actions import modulename"
#  - Add the module name to self.actionsoutput
#  - Add "self.actionsoutput['modulename'] in functions Mac.action()"
#

from modules.actions import ReverseName
from modules.actions import NmapScan

from modules.alerts import MysqlStore
from modules.alerts import SendMail


class Mac(object):
    """ The MAC object: Contains IP, MAC, Datetime, etc... """
    def __init__(self, mac='00:00:00:00:00:00', ip='0.0.0.0', datetime=datetime.datetime.now(), last_event_name='Unknown'):
        self.mac = mac
        self.ip = ip
        self.datetime = datetime
        self.last_event_name = last_event_name
        self.uid = hash(mac + ip)
        self.actionsoutput = {'ReverseName': '', 'NmapScan': ''}
        return

    def __hash__(self):
        return hash(self.mac)

    def __eq__(self, other):
        return (self.mac) == (other.mac)

    def __str__(self):
        return str(self.__dict__)

    def get_mac(self):
        return self.mac

    def get_ip(self):
        return self.ip    

    def get_uid(self):
        return self.uid    

    def set_mac(self, mac):
        self.datetime = datetime.datetime.now()
        self.mac = mac
        self.uid = hash(self.mac + self.ip)
        return

    def set_ip(self, ip):
        self.datetime = datetime.datetime.now()
        self.ip = ip
        self.uid = hash(self.mac + self.ip)
        return

    def set_last_event_name(self, last_event_name):
        self.datetime = datetime.datetime.now()
        self.last_event_name = last_event_name
        return

    def set_datetime(self):
        self.datetime = datetime.datetime.now()
        return

    def action(self):
        logger.info("[Event] %s: (%s) %s %s" % (self.last_event_name, self.datetime, self.mac, self.ip))
        # .action(mac, ip) on modules/actions/*.py 
        logger.debug('Running module: ReverseName...')
        self.actionsoutput['ReverseName'] = (ReverseName.action(self.mac, self.ip))
        logger.debug('Running module: NmapScan...')
        self.actionsoutput['NmapScan'] = (NmapScan.action(self.mac, self.ip))
        self.alert()
        return

    def alert(self):
        # .action(mac, ip, datetime, last_event_name, actionsoutput) on modules/alert/*.py
        logger.debug('Running module: SendMail...')
        #logger.debug(SendMail.alert(self.mac, self.ip, self.datetime, self.last_event_name, self.actionsoutput))
        logger.debug('Running module: MysqlStore...')
        logger.debug(MysqlStore.alert(self.mac, self.ip, self.datetime, self.last_event_name, self.actionsoutput))
        return


class App: 
    """ Listen for ARP packets on a specified interface and execute actions on 'who-has' or 'is-at' events """
    def __init__(self, logger):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/tty'
        self.stderr_path = '/dev/tty'
        self.pidfile_path =  '/var/run/arpaction.pid'
        self.pidfile_timeout = 5
        self.logger = logger
        #
        self.actioncooldown = 43200 # 12h
        self.iface = 'eth0' 
        self.ips = {}
        self._db_load()
        self.actionhistory = {}
    
    """ Called by python-deamon """ 
    def run(self):
        sniff(prn=self._arp_monitor_callback, filter="arp", iface=self.iface, store=0) 
 
    """ DB - Load the objects """
    def _db_load(self):
        if os.path.exists('db.pickle'):
            with open('db.pck', 'rb') as f:
                self.macs = cPickle.load(f)
                logger.info('Loaded %s entries from %s' % (len(self.macs), f))
        else:
            self.macs = {}
 
    """ DB - Save the objects dict """
    def _db_write(self):
        with open('db.pickle', 'wb') as f:
            cPickle.dump(self.macs, f, protocol=cPickle.HIGHEST_PROTOCOL)
            logger.info('Database saved to file %s' % (f))
    
    """ ARP Core functions """
    def _arp_monitor_callback(self, pkt):
        if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
            # --- ls(pkt) ---
            # hwtype     : XShortField          = 1               (1)
            # ptype      : XShortEnumField      = 2048            (2048)
            # hwlen      : ByteField            = 6               (6)
            # plen       : ByteField            = 4               (4)
            # op         : ShortEnumField       = 1               (1)
            # hwsrc      : ARPSourceMACField    = '00:0c:f1:fd:10:ff' (None)
            # psrc       : SourceIPField        = '192.0.0.39'    (None)
            # hwdst      : MACField             = '00:00:00:00:00:00' ('00:00:00:00:00:00')
            # pdst       : IPField              = '192.0.0.207'   ('0.0.0.0')
            macaddr = pkt.sprintf("%ARP.hwsrc%")
            ipaddr  = pkt.sprintf("%ARP.psrc%")

            if macaddr == '00:00:00:00:00:00': return
            if ipaddr == '0.0.0.0': return

            # 1. If the hash is known in the db, we already know it just update the time (last seen)
            # 2. Check if the IP address already exist and if the MAC is different = raise IP conflict
            # 3. Check if the MAC address already exist and if the IP is different = raise IP change for device
            # 4. Else = New device 

            # 1. If the hash(mac+ip) is already known just update the time (last seen)
            uid = hash(macaddr + ipaddr)
            for k, v  in self.macs.items():
                if uid == v.uid:
                    mac = self.macs[macaddr]
                    mac.set_datetime()
                    return

            for k, v  in self.macs.items():
                # 2. Check if the IP address already exist and if the MAC is not the same = raise IP conflict
                if ipaddr == v.ip and macaddr != v.mac:
                    if self.macs.has_key(macaddr):
                        if self._action_limiter(ipaddr):
                            mac = self.macs[macaddr]
                            mac.set_last_event_name("MAC changed for IP %s : was %s and is now %s (IP Conflict ?)" % (ipaddr, v.mac, macaddr))
                            mac.set_mac(macaddr)
                            mac.action()
                            self._db_write()
                    return
                # 3. Check if the MAC address already exist and if the IP is not the same = raise IP change for device
                if macaddr == v.mac and ipaddr != v.ip:
                    if self._action_limiter(macaddr):
                        mac = self.macs[macaddr]
                        mac.set_last_event_name("IP Changed for MAC %s : Was %s and is now %s" % (macaddr, v.ip, ipaddr))
                        mac.set_ip(ipaddr)
                        mac.action()
                        self._db_write()
                    return

            # 4. Else = New device
            mac = Mac(macaddr, ipaddr)
            mac.set_last_event_name("New device with mac: %s and ip: %s" % (macaddr, ipaddr))
            mac.action()
            # We add the mac object in the dict
            self.macs[mac.get_mac()] = mac
            self._db_write()

    """ Check last Action and return True if we can send one """
    def _action_limiter(self, identifier):
        # Never had any Actions: Allow
        if not self.actionhistory.has_key(identifier):
            self.actionhistory[identifier] = datetime.datetime.now()
            return True
        else:
            # Action is recent: Deny
            if self.actionhistory[identifier] > datetime.datetime.now() - datetime.timedelta(seconds=self.actioncooldown):
                return False
            # Action is old: Allow
            else:
                self.actionhistory[identifier] = datetime.datetime.now()
                return True


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'debug':
            # Run as DEBUG (Log to stdout: debug level)
            logger = logging.getLogger("DaemonLog")
            logger.addHandler(logging.StreamHandler())
            logger.setLevel(logging.DEBUG)
            App(logger).run()
            exit()
         
    # Run as DAEMON (Log to file: info level)
    handler = logging.FileHandler("arpaction.log")
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger = logging.getLogger("DaemonLog")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler) 
    app = App(logger)
    daemon_runner = runner.DaemonRunner(app)
    # This ensures that the logger file handle does not get closed during daemonization
    daemon_runner.daemon_context.files_preserve=[handler.stream]
    daemon_runner.do_action()
    
# vim: noai:ts=4:sw=4
