If ARP Then That
================

If ARP Then That is a simple daemon who can execute an
action on a ARP 'who-has' or 'is-at' event.

Ex: Run a nmap scan when a new host is discovered
on the network and push the information to a db/mail

There are only few modules available but you can
easily add your own as I tried to keep the program
quite modular.

License
-------
See LICENSE.md


Dependencies/Requirements
-------------------------
It's based on the exellent python-scapy library and 
the python-daemon package.

On Debian based systems a simple command like that 
should do the trick.

  aptitude install python-scapy python-daemon 


Usage
-----
To run the arpaction as a deamon, it's as simple as:

To start the process:
    python arpaction.py start

To stop the process:
    python arpaction.py stop

To restart the process:
    python arpaction.py restart

And to start in debug mode (no daemon, log to stdout):
    python arpaction.py debug


Modules
-------
There are two kind of modules:
    *   Actions: Are executed first on an event and the 
output result is stored
    *   Alerts: Are executed afterwards. Can access the
output result of Actions modules.

For now, I've written thoses:
    *   Actions:
        * ReverseName
        * NmapScan
    *   Alert
        * SendMail
        * MysqlStore


Configuration
-------------
This program is still in early development stage so you'll
have to edit arpaction.py to change the settings.
