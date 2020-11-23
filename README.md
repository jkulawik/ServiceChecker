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

Unfortunately I haven't found a way to include my API key in the app in a safe way, so for the time being you need to supply your own.
For that reason you will need an account on https://www.shodan.io/. It is free and it should only take a moment to register.

## Usage

* Launch the tool once (main.py).
* The tool will create a `shodan_api_key.txt` file.
* Paste your Shodan API key inside (you can copy it from the top of the website once you're logged in) and save the file.
* If everything is correct, the tool will work correctly after relaunching.
* Follow the command line hints.

## Contributing

More ports to scan are always welcome. Feel free to suggest them.

If you wish to contribute code, here are the most urgent tasks:
* Add subnet mask detection
* Add support for wider range of the ping sweep
* Improve multithreading performance
* Linux tests
* Sorting the ping sweep results (this is non-essential, just a nitpick really)
