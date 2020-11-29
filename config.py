
# NOTE: Changing these settings requires a restart of the tool.


# ===========PORT SCAN SETTINGS==========
# This is a list of ports that will be scanned by the tool.
# You can add more, just use the same format.
# Be aware it will take a little more time to scan, however.
services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    69: 'Trivial FTP',
    80: 'HTTP',
    2121: 'FTP (unofficial port)',
    2222: 'SSH (unofficial port)',
    2323: 'Telnet (unofficial port)',
}

# ===========MISC SETTINGS==========

skip_ping_sweep = False
# TBA

truncate_vendors = True
# Truncate vendor names to 30 signs, because some of them
# are very long (they include stuff like "Co. Ltd").
# You can turn this off for full names,
# but it will break the formatting for the long ones

limit_vendor_requests = True
# Disabling this will make host data acquirement a little faster,
# but some results will be rate limited ('Too Many Requests' error)

# ===========TIME SETTINGS==========
# Most services can answer in milliseconds on a home network.
# If the scans seem to not return anything, make the numbers bigger.
# It will slow down the scan, however.
# The time is given in seconds

port_timeout = 0.05

