
# NOTE: Changing these settings requires a restart of the tool.


# ===========PORT SCAN SETTINGS==========
# This is a list of ports that will be scanned by the tool.
# You can add more, just use the same format.
services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    69: 'Trivial FTP',
    80: 'HTTP',
    443: 'HTTPS',
    2121: 'FTP (unofficial port)',
    2222: 'SSH (unofficial port)',
    2323: 'Telnet (unofficial port)',
}

# Set this to true to skip the ping sweep and use your preferred IPs
# (for example when you know some host is in the network but it doesn't respond to pings)
custom_ips = False

# If the above is set to True, the tool uses this list:
manual_ip_list = ['192.168.1.1', '192.168.1.27', '192.168.1.32']

# ===========MISC SETTINGS==========

truncate_vendors = True
# Truncate vendor names to 30 signs, because some of them
# are very long (they include stuff like "Co. Ltd").
# You can turn this off for full names,
# but it will break the formatting for the long ones

# ===========PERFORMANCE SETTINGS==========

port_timeout = 0.05
# Most services can answer in milliseconds on a home network.
# If the scans seem to not return anything, make the numbers bigger.
# It will slow down the scan, however.
# The time is given in seconds

ping_threads = 16
# Number of threads for the ping sweep. Impacts scan time.
# You can experiment with it, but
# I found that more is not necessarily better in this case.
# Your computer might have a different sweet spot with this though.

limit_vendor_requests = True
# Disabling this will make host data acquirement a little faster,
# but some results will be rate limited ('Too Many Requests' error)

