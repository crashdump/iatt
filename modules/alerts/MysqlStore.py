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

import mysql.connector

con = None

def alert(mac, ip, datetime, last_event_name, actionsoutput):
    try:
        aoutput = ''
        for k, v in actionsoutput.items():
            aoutput = aoutput + '<action name="%s">%s</action>\r\n' % (k, v)

        con = mysql.connector.connect(
            host = "localhost",
            user = "mysql",
            password = "",
            database = "iatt"
        )

        cur = con.cursor()
        q = """INSERT INTO arpevents (datetime, mac, ip, lasteventname, actionsoutput) VALUES ('%s','%s','%s', '%s', '%s') ON DUPLICATE KEY UPDATE mac = '%s'""" % \
                                                                     (datetime, mac, ip, con.escape_string(last_event_name), con.escape_string(aoutput), mac)
        cur.execute(q)
        # data = cur.fetchone()
        con.commit()
        return "Pushed to the db."
    
    except mysql.connector.Error as e:
        print("Error %d: %s" % (e.args[0],e.args[1]))
        return "Error while inserting in db"
    
    finally:
        if con:
            con.close()
            return "Pushed to the db."


"""
You can use this php code to display the data in a browser:

<html>
<head>
    <title>Mac Map</title>
    <style type="text/css">
        table.db-table      { border-right:1px solid #ccc; border-bottom:1px solid #ccc; }
        table.db-table th{ background:#eee; padding:5px; border-left:1px solid #ccc; border-top:1px solid #ccc; }
        table.db-table td{ padding:5px; border-left:1px solid #ccc; border-top:1px solid #ccc; }
    </style>
</head>
<body>
<?php
$mysqli = new mysqli('localhost','arpaction','_youramazingpasswordhere_','arpaction');
/* check connection */
if (mysqli_connect_errno()) { printf("Connect failed: %s\n", mysqli_connect_error()); exit(); }
$query = "SELECT  `datetime`,  `mac`,  `ip`, `lasteventname`, `actionsoutput` FROM `arpaction`.`arpevents` ORDER BY `ip` ASC LIMIT 500;";
if ($result = $mysqli->query($query)) {
    print '<table cellpadding="0" cellspacing="0" class="db-table">'.PHP_EOL;
    print '<tr><th>Datetime</th><th>MAC</th><th>IP</th><th>Last Event</th><th>Hostname</th><th>Nmap</th></tr>'.PHP_EOL;
    /* fetch associative array */
    while ($row = $result->fetch_assoc()) {
        $string = preg_match_all('#^\<action name="(.*)"\>(.*)\</action\>#msU', $row["actionsoutput"], $actionsoutput);
        $action_modules_titles = $actionsoutput[1];
        $action_modules_results = $actionsoutput[2];
        print '<tr>'.PHP_EOL;
        print '<td>'.$row["datetime"].'</td>'.PHP_EOL;
        print '<td>'.$row["mac"].'</td>'.PHP_EOL;
        print '<td>'.$row["ip"].'</td>'.PHP_EOL;
        print '<td>'.substr($row["lasteventname"], 0, 10).'</td>'.PHP_EOL;
        print '<td>'.$action_modules_results[0].'</td>'.PHP_EOL;
        print '<td><span title="'.htmlspecialchars($action_modules_results[1]).'">'.substr($action_modules_results[1], 0, 64).'</span></td>'.PHP_EOL;
        print '</tr>'.PHP_EOL;
    }
    print '</table><br />'.PHP_EOL;
    /* free result set */
    $result->free();
}
/* close connection */
$mysqli->close();
?>
</body>
</html>

"""

# vim: noai:ts=4:sw=4
