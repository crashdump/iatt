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
It's based on the excellents scapy and python-daemon 
libraries.

        python3 -m venv env
        source env/bin/activate
        pip install -r requirements.txt

Usage
-----
To run the arpaction as a deamon, it's as simple as:

To start the process:

        python iatt.py start

To stop the process:

        python iatt.py stop

To restart the process:

        python iatt.py restart

And to start in debug mode (no daemon, log to stdout):

        python iatt.py debug


Modules
-------
There are two kind of modules:
 * Actions: Are executed first on an event, and the output result is stored
 * Alerts: Are executed afterwards. Can access the output result of Actions modules.

For now, I have implemented:

 *   Actions:
   * ReverseName
   * NmapScan
 *   Alert
   * SendMail
   * MysqlStore


Configuration
-------------
This program is still in early development stages, so you'll
have to edit arpaction.py to change the settings.
