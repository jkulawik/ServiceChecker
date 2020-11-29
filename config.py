
# NOTE: Changing these settings requires a restart of the tool.

skip_ping_sweep = False

# ===========TIME SETTINGS==========
# Most services can answer in miliseconds on a home network.
# If the scans seem to not return anything, make the numbers bigger.
# It will slow down the scan, however.
# Give time in seconds

port_timeout = 0.05


# ===========PORT SCAN SETTINGS==========
# This is a list of ports that will be scanned by the tool.
# You can add more, just use the same format.
# Be aware it will take more time to scan, however.
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
