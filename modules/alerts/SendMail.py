#!/usr/bin/env python
# -*- coding: utf-8 -*-

import smtplib
from email.mime.text import MIMEText

sender = 'macalert@monitoring'
recipient = 'adrienp@aac-services.co.uk'

def alert(mac, ip, datetime, last_event_name, actionsoutput):
    try:
        body = "****** Device Informations ******\n"
        body = body + "MAC: %s\n" % mac
        body = body + "IP: %s\n" % ip 
        body = body + "Timestamp: %s" % datetime 
        
        for k, v in actionsoutput.items():
            body = body + "\n\n**** %s ****\n" % k
            body = body + "%s" % v
        
        body = body + "\n*********************************"

        msg = MIMEText(body)
        msg['Subject'] = last_event_name
        msg['From'] = sender
        msg['To'] = recipient

        # Send the message via our own SMTP server, but don't include the envelope header.
        s = smtplib.SMTP('172.31.0.25')
        s.sendmail(sender, recipient, msg.as_string())
        s.quit()

        #return '\n' + msg.as_string()
        return 'Mail sent to: %s' % recipient
    except:
        return None

# vim: noai:ts=4:sw=4
