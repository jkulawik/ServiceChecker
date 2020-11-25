# Internet interaction imports
from requests import get  # Get external IP
import shodan_ip_check

# Ping sweep imports
import ping_sweep

# Passive scan
import dhcp_listener
import simple_mail  # For alerts

# LAN scan
import multiprocessing
import socket
from scapy.layers.l2 import getmacbyip

# Utilities
import time
import pprint


# Initialisations
socket.setdefaulttimeout(1.0)  # This is for the scans to be faster
# End initialisations


# TODO Debug, can be deleted in final version
def print_type(arg):
    print("Data type: {}".format(type(arg)))

# Port scan functions


services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    69: 'Trivial FTP',
    2121: 'FTP (unofficial port)',
    2222: 'SSH (unofficial port)',
    2323: 'Telnet (unofficial port)',
}


# Thread job
def port_scan(job_q, results_q):
    while True:
        ip = job_q.get()
        if ip is None:
            break

        open_ports = []
        ports = list(services.keys())

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        output_data = [ip, open_ports]
        results_q.put(output_data)


# This is almost the same as ping_sweep. Check that file for documentation
def scan_ports(ip_list):
    start_time = time.time()
    pool_size = len(ip_list)

    print('Scanning for open ports on found hosts...')

    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=port_scan, args=(jobs, results))
            for i in range(pool_size)]
    for p in pool:
        p.start()

    for ip in ip_list:
        jobs.put(ip)

    for p in pool:
        jobs.put(None)
    for p in pool:
        p.join()

    ip_ports = []
    while not results.empty():
        ip_ports.append(results.get())

    print('Port scan finished.')
    print("Scan duration: {} seconds".format(time.time() - start_time))

    # The result is a list with [ ip, open_ports[] ] in each entry
    return ip_ports


# Gets the ports of the given IP from a list of elements of this kind: [ ip, open_ports[] ]
# Example: Takes a list of elements like this: ['192.168.1.32', [21, 22, 23]]
# and returns [21, 22, 23]
# This isn't very efficient, but has to do for now...
def get_ports(ip, ip_ports):
    for entry in ip_ports:
        if ip in entry:
            return entry[1]


def get_lan_ip():
    # TODO ensure this uses the correct interface and not smth virtual
    ip = socket.gethostbyname(socket.gethostname())
    return ip


# Check if given IP (string format) is a LAN IP:
def ip_check_local(ipl):
    if not (ipl.startswith('192.168.') or ipl.startswith('10.') or ipl.startswith('17.')):
        # Check if IP is between 172.16.0.0 and 172.31.255.255.
        octets = ipl.split('.')
        octet2 = int(octets[1])
        if octet2 < 16 or octet2 > 31:
            return False
    else:
        return True


def local_scan():
    ipl = get_lan_ip()  # Local IP

    print('\nYour local IP is: {}'.format(ipl))

    if ip_check_local(ipl) is False:
        print('Your address does not appear to be from a local network. Aborting scan.')
    else:
        print('Note: currently the program can only scan the addresses in the last IP octet range (like in a /24 '
              'subnet).')

        ip_list = ping_sweep.get_ip_list(ipl)
        # TODO The scan takes too long for testing other things.
        #  Substitute with a direct list for now and remove it later
        #ip_list = ['192.168.1.1', '192.168.1.27', '192.168.1.32']

        # TODO sort the IPs
        # print(ip_list)

        data_list = []
        open_ports_found = False
        open_ports = []
        ip_ports = scan_ports(ip_list)

        # Get host data
        for address in ip_list:
            host_data = socket.gethostbyaddr(address)
            # host_data structure is: (name, aliases, [IPs])

            ip_addr = host_data[2][0]
            hostname = host_data[0]
            ports = get_ports(address, ip_ports)
            mac_addr = str(getmacbyip(address))

            ip_data = [
                ip_addr,
                hostname,
                ports,
                mac_addr
            ]

            data_list.append(ip_data)

        print('\nNote: MAC address None might mean the host is offline at the moment.\n'
              'Your host might return ff:ff:ff:ff:ff:ff.\n')

        # Display hosts with found ports
        print("{:<15} {:<20} {:<20} {}".format('IP', 'Name', 'MAC', 'List of open ports'))
        print("{:<15} {:<20} {:<20} {}".format('-'*15, '-'*16, '-'*17, '-'*18))

        for entry in data_list:
            print("{:<15} {:<20} {:<20} {}".format(entry[0], entry[1], entry[3], entry[2]))

            if len(entry[2]) != 0:
                open_ports_found = True
                for port in entry[2]:
                    if port not in open_ports:
                        open_ports.append(port)

        if open_ports_found:
            print('\nPorts belonging to potentially dangerous services have been found on one or more of\n'
                  'the devices in your local network. Make sure to investigate and close or secure them.')

            print('\nThe services on those ports are:')
            for port in open_ports:
                print('─ {} ({})'.format(port, services.get(port)))

        else:
            print('\nNo ports belonging to potentially dangerous services have been found.')

# End port scan functions


def main():

    # Test hosts:
    # ip = '24.158.43.67'  # Test host - vulnerable
    ip = '40.114.177.156 '  # Duckduckgo.com
    # ip = '8.8.8.8' # Test host - Google DNS

    print('\n----Service Checker----\n')

    while True:
        print("\nWhat would you like to do?")
        command = input("Type:\n"
                        "1 to check your external IP on Shodan\n"
                        "2 to scan your local network\n"
                        "3 to start monitoring the network\n"
                        "4 to test e-mail notifications\n"
                        "q to exit\n")
        if command == 'q':
            quit()
        elif command == '1':
            # Get router IP
            # ipify is open source and free; no visitor information is logged.
            # ip = get('https://api.ipify.org').text # TODO uncomment for final release
            shodan_ip_check.check_shodan(ip)
        elif command == '2':
            print('\nThe tool will now scan your local network for hosts and chosen opened ports.')
            # TODO give the choice to add shodan ports?
            #input("\nPress Enter to continue...")
            local_scan()
        elif command == '3':
            dhcp_listener.start_sniffing()
        elif command == '4':
            simple_mail.send('Test', 'This is a test message content.')
        else:
            print('Wrong command.')
        # input("\nPress Enter to go back to the menu...") # TODO flush the input buffer if this is to work


if __name__ == "__main__":
    main()
