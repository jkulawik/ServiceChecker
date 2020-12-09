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

# Banner grabbing
import telnetlib
import ssl

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


def prune_whitechars_at_ends(message):
    while message.endswith('\n') or message.endswith('\r'):
        message = message[:-1]
    while message.startswith('\n') or message.startswith('\r') or message.startswith(' '):
        message = message[1:]

    return message

# LAN scan functions


# Check configs. E.g. check_port_type(22, 'SSH') returns true
def check_port_type(port, service):
    description = services.get(port)
    return service in description


# Thread job
# service_dict had to be passed to be compatible with the thread scheduler :(
def banner_grab(job_q, results_q, service_dict):
    while True:
        ports_by_ip = job_q.get()  # e.g. ['192.168.1.32', [21, 22, 23]]
        if ports_by_ip is None:
            break

        ip_address = ports_by_ip[0]
        ports = ports_by_ip[1]
        banner_list = []

        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.05)
            status = s.connect_ex((ip_address, port))
            if status != 0:
                # Skip unresponsive sockets
                continue

            if check_port_type(port, 'HTTPS'):
                s = ssl.wrap_socket(s, keyfile=None, certfile=None,
                                    server_side=False, cert_reqs=ssl.CERT_NONE,
                                    ssl_version=ssl.PROTOCOL_SSLv23)

            if check_port_type(port, 'HTTP'):
                # message = b'hello\r\n'
                message = b'HEAD HTTP/1.1 \r\n'
                # message = b'GET HTTP/1.1 \r\n'
            elif check_port_type(port, 'DNS'):
                message = b'version.bind. CHAOS TXT\r\n'
            else:
                message = b''
                # message = b'\r\n\r\n'
                # message = b'help\r\n'

            banner = b'Tool issue'  # Init to not raise further exceptions when a socket throws an exception
            # Catching exceptions is bad for performance, but has to be done
            # because socket.receive always throws exceptions rather than returning error codes
            try:
                if check_port_type(port, 'Telnet'):
                    tn = telnetlib.Telnet(ip_address, port)
                    banner = tn.read_until(b'ogin', 3)  # Read until the login prompt
                    tn.close()
                else:
                    # Many servers send data without even probing them, and in that case a probe can be disruptive.
                    if message != b'':
                        s.send(message)
                    banner = s.recv(1024)
                    s.close()
            except Exception as exc:
                exc_str = "Exception " + str(exc.__class__) + " occurred."
                banner = bytes(exc_str, 'iso-8859-1')

            banner_txt = banner.decode('iso-8859-1')
            banner_txt = prune_whitechars_at_ends(banner_txt)

            if 'HTTP' in banner_txt:
                print('[i] {}'.format(banner_txt))

                if 'Server' not in banner_txt:
                    banner_txt = '[-] Server not in HTTP banner.'
                else:
                    banner_lines = banner_txt.splitlines()

                    for line in banner_lines:
                        if 'Server' in line:
                            banner_txt = '[+] {}'.format(line)
            else:
                # print(str(banner))
                if banner_txt == '':
                    banner_txt = '[-] Empty response'
                elif 'xception' in banner_txt:
                    banner_txt = '[-] {}'.format(banner_txt)
                else:
                    banner_txt = '[+] {}'.format(banner_txt)

            banner_list.append([port, banner_txt])

        output_data = [ip_address, banner_list]
        # Resultant row of data:
        # [
        # '192.168.1.32',
        # [  [21, 'ftp banner'], [22, 'SSH banner'], [23, 'telnet banner']  ]
        # ]
        results_q.put(output_data)


# Thread job.
# The result of using it with multithread_scan is a list with [ ip, open_ports[] ] in each entry
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
def multithread_scan(job_list, scan_job):
    start_time = time.time()
    pool_size = len(job_list)

    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=scan_job, args=(jobs, results, services))
            for i in range(pool_size)]
    for p in pool:
        p.start()

    for job in job_list:
        jobs.put(job)

    for p in pool:
        jobs.put(None)
    for p in pool:
        p.join()

    result_list = []
    while not results.empty():
        result_list.append(results.get())

    print("Scan finished. Duration: {} seconds".format(time.time() - start_time))

    return result_list


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


# This is a substitute for ping sweep
# Takes an IP and generates a list with the assumption of the net being /24
def generate_ips(ip):
    octets = ip.split('.')
    net_prefix = octets[0] + '.' + octets[1] + '.' + octets[2]

    ip_list = []
    # TODO this is in testing, the final range should be up to 255
    for i in range(1, 20):
        ip_list.append(net_prefix+'.{}'.format(i))
    return ip_list


def local_scan():
    ipl = get_lan_ip()  # Local IP

    print('\nYour local IP is: {}'.format(ipl))

    if ip_check_local(ipl) is False:
        print('Your address does not appear to be from a local network. Aborting scan.')
    else:

        x = config.ip_list_setting
        if x == 3:
            print('Skipping ping sweep.')
            print('Scanning all IPs in the last IP octet range (like in a /24 subnet).')
            ip_list = generate_ips(ipl)
        elif x == 2:
            print('Skipping ping sweep.')
            print('Scanning manually entered IPs.')
            ip_list = config.manual_ip_list
        else:
            print('Ping sweeping the IPs in the last IP octet range (like in a /24 subnet).')
            ip_list = ping_sweep.get_ip_list(ipl)

        print(ip_list)

        data_list = []
        open_ports_found = False
        open_ports = []

        print('Scanning for open ports on found hosts...')
        ports_by_ip = multithread_scan(ip_list, port_scan)

        print('Acquiring host data...')
        start_time = time.time()
        for address in ip_list:
            mac_addr = str(getmacbyip(address))  # TODO this needs a timeout for optimisation

            # This means host was unresponsive
            # It only matters when skipping ping sweep
            if mac_addr == 'None':
                continue

            host_data = socket.gethostbyaddr(address)
            hostname = host_data[0]  # host_data structure is: (name, aliases, [IPs])
            vendor = mac_vendor.get_str(mac_addr)

            ports = get_ports(address, ports_by_ip)
            ports.sort()

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

            open_ports.sort()

            print('\nThe services on those ports are:')
            for port in open_ports:
                print('─ {} ({})'.format(port, services.get(port)))

        else:
            print('\nNo ports belonging to potentially dangerous services have been found.')

        if open_ports_found:
            decision = 'Y'  # input('Grab banners? Enter Y or n \n')
            if decision == 'Y':
                print('Grabbing banners for all services. This might take a minute...')
                banner_data = multithread_scan(ports_by_ip, banner_grab)
                #pprint.pprint(banner_data)
                for row in banner_data:
                    ip_address = row[0]

                    host_data = socket.gethostbyaddr(ip_address)
                    hostname = host_data[0]

                    banner_by_port_list = row[1]
                    print('{} ({})'.format(ip_address, hostname))

                    for entry in banner_by_port_list:
                        port = entry[0]
                        banner = entry[1]
                        print('\tPort: {}'.format(port))
                        print('\t\t{}'.format(banner))


# End port scan functions


# ==================================================================================================================== #
# ====================================================MAIN============================================================ #
# ==================================================================================================================== #


def main():

    # Test hosts:
    ip = '24.158.43.67'  # Test host - vulnerable
    # ip = '40.114.177.156 '  # Duckduckgo.com
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
            # pprint.pprint(services)

            tst = prune_whitechars_at_ends(' \r\nmny test jesse\n\r')
            print('start')
            print('{}end'.format(tst))

            #quit()
        else:
            print('Wrong command.')
        # input("\nPress Enter to go back to the menu...") # TODO flush the input buffer if this is to work


if __name__ == "__main__":
    main()
