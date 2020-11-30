# Internet interaction imports
from sc_utils import shodan_ip_check

# Ping sweep imports
from sc_utils import ping_sweep

# Passive scan
from sc_utils import dhcp_listener
from sc_utils import simple_mail  # For alerts

# LAN scan
import multiprocessing
import socket
from scapy.layers.l2 import getmacbyip
from sc_utils import mac_vendor
import config

# Utilities
import time
import pprint


# Initialisations
services = config.services
socket.setdefaulttimeout(config.port_timeout)  # This is for the scans to be faster
# End initialisations


# TODO Debug, can be deleted in final version
def print_type(arg):
    print("Data type: {}".format(type(arg)))

# Port scan functions


# Thread job
def port_scan(job_q, results_q, service_dict):
    while True:
        ip = job_q.get()
        if ip is None:
            break

        open_ports = []
        # This needs to be passed as an argument to use the same instance in each thread
        ports = list(service_dict.keys())

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

    pool = [multiprocessing.Process(target=port_scan, args=(jobs, results, services))
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
def get_ports(ip, ip_ports):
    # This could be faster, but isn't affecting the performance too much
    for entry in ip_ports:
        if ip in entry:
            return entry[1]


def get_lan_ip():
    # TODO ensure this uses the correct interface and not smth virtual
    host_name = socket.gethostname()
    ip = socket.gethostbyname(host_name)
    return ip


# TODO use this to print ---- above the results table... or delete it
def get_biggest_len(_list):
    max_len = -1
    for element in _list:
        if len(element) > max_len:
            max_len = len(element)


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

        if config.custom_ips:
            print('Scanning manually entered IPs.')
            ip_list = config.manual_ip_list
        else:
            print('Note: currently the program can only scan the addresses '
                  'in the last IP octet range (like in a /24 subnet).')
            ip_list = ping_sweep.get_ip_list(ipl)

        # print(ip_list)

        data_list = []
        open_ports_found = False
        open_ports = []
        ip_ports = scan_ports(ip_list)

        # Get host data
        print('Acquiring host data...')
        start_time = time.time()
        for address in ip_list:
            ports = get_ports(address, ip_ports)
            hostname = 'Host may be down'

            try:
                host_data = socket.gethostbyaddr(address)
                hostname = host_data[0]  # host_data structure is: (name, aliases, [IPs])
            except:
                pass

            mac_addr = str(getmacbyip(address))
            vendor = mac_vendor.get_str(mac_addr)

            ip_data = [
                address,
                hostname,
                ports,
                mac_addr,
                vendor
            ]

            data_list.append(ip_data)

        print("Duration: {} seconds".format(time.time() - start_time))
        # TODO sort the data_list

        print('\nNote: Your host might return ff:ff:ff:ff:ff:ff.\n')

        # Display hosts with found ports
        print("{:<15} {:<20} {:<20} {:<35} {}".format('IP', 'Name', 'MAC', 'Vendor', 'List of open ports'))
        print("{:<15} {:<20} {:<20} {:<35} {}".format('-'*15, '-'*16, '-'*17, '-'*30, '-'*18))

        for entry in data_list:
            print("{:<15} {:<20} {:<20} {:<35} {}".format(entry[0], entry[1], entry[3], entry[4], entry[2]))

            if len(entry[2]) != 0:
                open_ports_found = True
                for port in entry[2]:
                    if port not in open_ports:
                        open_ports.append(port)

        if open_ports_found:
            print('\nPorts belonging to potentially vulnerable services have been found on one or more of\n'
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
                        "4 to run the current test\n"
                        "q to exit\n")
        if command == 'q':
            quit()
        elif command == '1':
            # Get router IP
            # ipify is open source and free; no visitor information is logged.
            # ip = get('https://api.ipify.org').text # TODO uncomment for final release
            new_ports = shodan_ip_check.check_shodan(ip)

            # Adding the detected ports to the scan list:
            for port in new_ports:
                if port not in services:
                    services.update({port: 'Port detected on Shodan'})
                    #config.services[port] = 'Port detected on Shodan'
        elif command == '2':
            print('\nThe tool will now scan your local network for hosts and chosen opened ports.')
            local_scan()
        elif command == '3':
            dhcp_listener.start_sniffing()
        elif command == '4':
            # Mail tests
            #simple_mail.send('Test', 'This is a test message content.')
            #get_mac_details('d8:e0:e1')  # Already truncated for security reasons; full mac works though.

            # Listener log tests
            #dhcp_listener.pal_time()
            #dhcp_listener.log('mny test...')

            # Service list test
            pprint.pprint(services)
            #quit()
        else:
            print('Wrong command.')
        # input("\nPress Enter to go back to the menu...") # TODO flush the input buffer if this is to work


if __name__ == "__main__":
    main()
