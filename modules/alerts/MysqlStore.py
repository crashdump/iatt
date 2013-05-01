#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CREATE TABLE `arpevents` (
    `datetime` DATETIME NOT NULL,
    `mac` CHAR(18) NOT NULL,
    `ip` CHAR(20) NOT NULL,
    `lasteventname` MEDIUMTEXT NOT NULL,
    `actionsoutput` MEDIUMTEXT NOT NULL,
    PRIMARY KEY (`mac`)
)
ENGINE=InnoDB;
"""

import MySQLdb as mdb
import sys

con = None

def alert(mac, ip, datetime, last_event_name, actionsoutput):
    try:
        aoutput = ''
        for k, v in actionsoutput.items():
            aoutput = aoutput + '<action name="%s">%s</action>\r\n' % (k, v)

        con = mdb.connect('localhost', 'arpaction', '_amazingpassword_', 'arpaction');
        cur = con.cursor()
        q = """INSERT INTO arpevents (datetime, mac, ip, lasteventname, actionsoutput) VALUES ('%s','%s','%s', '%s', '%s') ON DUPLICATE KEY UPDATE mac = '%s'""" % \
                                                                     (datetime, mac, ip, con.escape_string(last_event_name), con.escape_string(aoutput), mac)
        cur.execute(q)
        data = cur.fetchone()
        con.commit()
        return "Pushed to the db."
    
    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0],e.args[1])
        return "Error while inserting in db"
    
    finally:
        if con:
            con.close()
            return "Pushed to the db."

# vim: noai:ts=4:sw=4
