# ServiceChecker

This Python tool checks the security of your home network (or any LAN really).

The tool was made with IoT in mind, but it will moreso work with regular computers.

Features:
* Check your public IP (the address of your router) on Shodan
  * Lists ports visible to the outside world
  * Tries to identify the services running on them
  * Lists vulnerabilities found based on software versions and data about them
* Local network scanner
  * Finds running devices
  * Checks and displays the host names, IPs, MAC addresses and vendors to make devices easier to identify.
  * Scans for open TCP ports (which hint at potentially vulnerable services running). The port list is configurable, but some common and dangerous ones are listed out-of-the-box.
* Passive DHCP scanner that will let you monitor network access attempts. It features logging to text files and a MAC whitelist.

## Disclaimers

Note that the tool currently does not detect UDP ports.

This tool makes use of `shodan.io`, `ipify.org` and `macvendors.com` APIs.
* Shodan is a service which scans all IPs for vulnerabilities and open ports. Querying it does not pose any danger, as they have that data already.
* Ipify is used to get your public IP address, which is a regular activity done by all websites. It is open source and free. No visitor information is logged.
* MACVendors is a service which returns the manufacturer of a given MAC address. Since MAC precisely identifies a device, only a half of it is sent for privacy reasons. That half is sufficient and only suitable for vendor identification. It should not be a privacy risk at all, but keep that in mind.

Currently the LAN scan feature scans quite aggressively. You might experience some slow-downs, especially on the scanning device. Also be aware that this can potentially raise alarms in network security systems, if your LAN has one.

## Prerequisites

Use the command: `pip install -r requirements.txt` to install the dependencies. On Windows you can also execute the `Install.bat` file instead.

Unfortunately I haven't found a way to safely include my Shodan API key in the app, so for the time being you need to supply your own (it is not needed to use most features of this tool though).
For that reason you will need an account on https://www.shodan.io/. It is free and it should only take a moment to register.

## Usage

Launch the tool (`main.py`) and follow the command line hints.

### Configuration

You can edit certain parameters (the port scan list, most importantly) in the `config.py` file. The program might need a restart to register changes in that file.

Open it for more data, each parameter is commented.

### Using the Shodan look-up

If you wish to use the Shodan check, follow these steps to add a Shodan API key. The other functionalities can work without the key.

* Pick the Shodan option. A `shodan_api_key.txt` file will be created if one doesn't exist.
* Paste your Shodan API key inside (you can copy it from the top of the website once you're logged in) and save the file.
* If everything is correct, the Shodan check will work correctly without relaunching.
* You don't need to relaunch the program to change the key, it is reloaded at runtime.

If any ports are detected by Shodan that aren't in the service list, they will get added to the LAN scan list. This happens during runtime, so they won't be in the list when you relaunch the tool.

### Using the LAN scanner

Please be aware of the limitations caused by how this tool works:
* The tool determines your local IP and assumes a /24 subnet mask (due to considerable issues with getting the network mask via Python)
* Hence it can currently only scan the addresses in the last IP octet range (`X.X.X.1` - `X.X.X.255`). It should be sufficient for standard home networks, however.
* The tool then does a ping sweep to find active hosts in the network. Not all devices are pingable at all times - e.g. Android phones put the Wifi to sleep for battery saving and might not respond consistently. Some devices aren't pingable at all. **Note that devices which don't respond to ping won't be scanned.**
* To combat this, it is also possible to scan IPs from a list. You can use this setting by editing the config file.

### Using the DHCP scanner

The scanner creates separate logs for each day in the `/logs` folder.

Run the DHCP scanner once to create a `MAC_whitelist.txt` file. Put MAC addresses there line by line. They won't show up in logs. The list is read on the fly, so you don't need to restart the program to add new addresses. The file can contain other text, so you can make comments. There is no need to use any syntax, although I used `#` in this example:

```
# Phone:
40:XX:db:XX:XX:XX
# Laptop:
c8:XX:00:XX:XX:XX
```

Some devices refresh IPs from time to time, and some devices will attempt to connect without your knowledge to e.g. connect to a manufacturer server, so you might find the whitelist useful.

DHCP uses broadcasting, which means that this scanner only has to listen and doesn't use up your bandwidth at all. You should be able to leave it running without a big footprint - or start it when you connect a new device to see it connecting. If the device is still connected to the LAN, you can use the LAN scanner feature to check the device for open ports.

Note: Devices which already are connected will not show in the logs, as they already have their IPs in the LAN. Reconnecting devices should show up in the logs, however.

## Issues

Sometimes when scanning a local network, the tool will choose the wrong interface, for example a VMware one.
In my case I am expecting `192.168.1.27` as my address, but I sometimes I get `192.168.56.1`.
This seems to happen when I have another terminal open or when using an IDE, but there might be other reasons too.

For users: make sure that the local IP in the tool matches the IP you use for network access. Instructions:
* [Windows](https://www.wikihow.com/Check-a-Computer-IP-Address) (make sure you're checking the IP from wireless or ethernet, whichever you use, and not something else)
* [Mac](https://www.wikihow.com/Find-Your-IP-Address-on-a-Mac)
* Linux - `ip a` or `ifconfig`

If the IP doesn't match, stop any programs that might interfere and try the scan again.

## Contributing

More ports to scan are always welcome. Feel free to suggest them.

If you wish to contribute code, here are the most urgent tasks:
* UDP port scans
* Add subnet mask detection
* Add support for wider range of the ping sweep
* Improve multithreading performance
* Linux tests
* Sorting the ping sweep results (this is non-essential, just a nitpick really)
