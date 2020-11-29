

skip_ping_sweep = False

# This is a list of ports that will be scanned by the tool.
# You can add more, just use the same format.
# Be aware it will take more time to scan, however.
services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    69: 'Trivial FTP',
    2121: 'FTP (unofficial port)',
    2222: 'SSH (unofficial port)',
    2323: 'Telnet (unofficial port)',
}
