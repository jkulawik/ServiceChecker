# ServiceChecker

This Python tool checks the security of your home network (or any LAN really).

The tool was made with IoT in mind, but it will moreso work with regular computers.

Features:
* Check your public IP (the address of your router) on Shodan
  * Lists ports visible to the outside world
  * Tries to identify the services running on them
  * Lists vulnerabilities found based on software versions and data about them
* Scan the local network
  * The tool does a ping sweep to find active hosts in the network
  * Note: Due to considerable issues with getting the network mask via Python,
the tool can currently only scan the addresses in the last IP octet range (like in a /24 subnet).
  * Checks and displays the host names to make them easier to identify.
  * [PLANNED] Check for running services:
    * Telnet
    * FTP
    * SSH (?)
    * HTTP-XML authentication (big question mark)
  * [PLANNED?] Check for default credentials on those services


