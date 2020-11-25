# ServiceChecker

This Python tool checks the security of your home network (or any LAN really).

The tool was made with IoT in mind, but it will moreso work with regular computers.

Features:
* Check your public IP (the address of your router) on Shodan
  * Lists ports visible to the outside world
  * Tries to identify the services running on them
  * Lists vulnerabilities found based on software versions and data about them
* Scan the local network
  * The tool determines your local IP to find your network prefix.
  * The tool presumes a /24 subnet mask (due to considerable issues with getting the network mask via Python),
and hence can currently only scan the addresses in the last IP octet range (`X.X.X.1` - `X.X.X.255`). It should be sufficient for standard home networks, however.
  * The tool then does a ping sweep to find active hosts in the network (please note that not all devices are pingable at all times - e.g. Android phones put the Wifi to sleep for battery saving and might not respond consistently. This means they will be skipped in the port scan later, too).
  * Check and display the host names to make them easier to identify.
  * Scan for open ports (which hint at vulnerable services running):
    * Telnet
    * FTP
    * SSH
    * HTTP-XML authentication (planned?)
  * [PLANNED?] Check for default credentials on those services

## Prerequisites

Make sure you install the dependencies from the supplied list. This step might be automated or deprecated in the future.

Unfortunately I haven't found a way to safely include my API key in the app, so for the time being you need to supply your own (it is not needed to use most features of this tool though).
For that reason you will need an account on https://www.shodan.io/. It is free and it should only take a moment to register.

## Usage

Launch the tool (`main.py`) and follow the command line hints.

**If you wish to use the Shodan check, follow these steps. The other functionalities can work without the key.**
* Pick the Shodan option. A `shodan_api_key.txt` file will be created if one doesn't exist.
* Paste your Shodan API key inside (you can copy it from the top of the website once you're logged in) and save the file.
* If everything is correct, the Shodan check will work correctly without relaunching.
* You don't need to relaunch the program to change the key, it is reloaded at runtime.

## Issues

Sometimes when scanning a local network, the tool will choose the wrong interface, for example a VMware one.
In my case I am expecting `192.168.1.27` as my address, but I sometimes I get `192.168.56.1`.
This seems to happen when I have another terminal open, but there might be other reasons too.

For users: make sure that the local IP in the tool matches the IP you use for network access. Instructions:
* [Windows](https://www.wikihow.com/Check-a-Computer-IP-Address) (make sure you're checking the IP from wireless or ethernet, whichever you use, and not something else)
* [Mac](https://www.wikihow.com/Find-Your-IP-Address-on-a-Mac)
* Linux - `ip a` or `ifconfig`

If the IP doesn't match, stop any programs that might interfere and relaunch the tool.

## Contributing

More ports to scan are always welcome. Feel free to suggest them.

If you wish to contribute code, here are the most urgent tasks:
* Add subnet mask detection
* Add support for wider range of the ping sweep
* Improve multithreading performance
* Linux tests
* Sorting the ping sweep results (this is non-essential, just a nitpick really)
