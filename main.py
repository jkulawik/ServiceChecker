# Internet interaction imports
from shodan import Shodan
from requests import get

# Ping sweep imports
import multiprocessing
import subprocess

# Utilities
import platform
import socket  # To query the LAN
socket.setdefaulttimeout(1.0)

from os import path
import time
import pprint

# Initialisations
OP_SYS = platform.system()
api_file = "shodan_api_key.txt"
if not path.exists(api_file):
    open(api_file, "w+")
    print('Shodan API file created.\nPlease paste your key inside and restart the tool.')
    quit()
else:
    file = open(api_file, "r")
    API_KEY = file.read(32)
    file.close()
    api = Shodan(API_KEY)

# End initialisations


# TODO Debug, can be deleted in final version
def print_type(arg):
    print("Data type: {}".format(type(arg)))



def get_cvss_severity(score):
    score = float(score)
    base = "Severity: "
    if score == 0.0:
        return base + "None"
    if score < 3.9:
        return base + "Low"
    if score < 6.9:
        return base + "Medium"
    if score < 8.9:
        return base + "High"
    else:
        return base + "Critical"


def check_shodan(ip):
    try:
        ipinfo = api.host(ip)
        #pprint.pprint(ipinfo)  # TODO remove this later

        port_data = ipinfo["data"]  # Info per port

        # -------Summary-------
        print('Note: The following data is collected from an outside service.\n'
              'Use common sense on whether or not it is up to date.')
        print('Last update: {}\n'.format(ipinfo['last_update']))

        port_count = len(port_data)
        print("Detected {} reachable ports.".format(port_count))
        if port_count > 0:
            print('Ports available from your IP are: {}'.format(ipinfo["ports"]))
            print('\nMake sure if exposing these services is desired.')
            print('If it is not, and  you are not accessing your device/network from outside,\n'
                  'it would be best to turn off those services and/or block the discovered ports from\n'
                  'being available on the Internet by changing the firewall settings on your router.')
        else:
            print('The device/network seems to be secure.')

        print('')  # Break line

        if 'vulns' in ipinfo:
            tmp = len(ipinfo['vulns'])
            print('{} unique* vulnerabilities detected.'.format(tmp))
            print('*they might repeat on different ports')
            print(
                'DISCLAIMER: The device(s) may not be impacted by all of these issues. The vulnerabilities are implied '
                'based on the software and version.')
            print('Please see full scan to see more information.')
        else:
            print('No well-known vulnerabilities detected on the opened ports.')

        # -------End of the summary-------
        input("\nPress Enter to display full scan data...")

        print('\nScan data:')
        print('│')
        for entry in port_data:
            # pprint.pprint(entry)
            print('├──Port: {}'.format(entry['port']))
            # -------Service name-------
            tmp = entry['_shodan']
            tmp = tmp['module']
            print('│\t├──Service candidate: {}'.format(tmp))

            # -------Product name-------
            if 'product' in entry:
                print('│\t├──Product: {}'.format(entry['product']))
            else:
                print('│\t├──Product: (Unspecified)')

            # -------Product name-------
            if 'tags' in entry:
                print('│\t├──Tags: {}'.format(entry['tags']))

            # -------HTTP info-------
            if 'http' in entry:
                http_data = entry['http']
                if 'title' in http_data:
                    print('│\t├──HTTP app detected: {}'.format(http_data['title']))
                else:
                    print('│\t├──HTTP app detected, but its name could not be found.')

            # -------Vulnerabilities-------
            if 'vulns' in entry:
                vulns = entry['vulns']
                # print(vulns)
                for vuln in vulns:
                    key = str(vuln)
                    print('│\t\t├──Vulnerability: {}'.format(key))
                    vuln_data = vulns[key]
                    # print(vuln_data)
                    score = vuln_data['cvss']
                    print('│\t\t│\t├──Severity score (CVSS standard): {}/10'.format(score))
                    print('│\t\t│\t├──{}'.format(get_cvss_severity(score)))
                    print('│\t\t│\t├──Summary: ')  # TODO This needs better formatting
                    # pprint.pprint(vuln_data['summary'])
                    print('│\t\t│\t├──{}'.format(vuln_data['summary']))
                    # vuln_data['references'] # This is a list
                    # vuln_data['summary']

    except Exception as exc:
        info = exc.__dict__
        if info["value"] == "No information available for that IP.":
            print(info["value"])
            print('That most likely means that your network is safe (not available from the Internet).')
        else:
            print("Exception", exc.__class__, "occurred.")
            print(info["value"])
# END SHODAN SEARCH FUNCTION

# Ping sweep functions

# Thread job
def pinger(job_q, results_q):
    while True:
        ip = job_q.get()
        if ip is None:
            break

        try:
            timeout = '1'
            packet_count = '1'

            if OP_SYS == 'Windows':
                proc = subprocess.Popen(['ping.exe', '-n', packet_count, '-w', timeout, ip], stdout=subprocess.PIPE)
                output = proc.stdout.read()  # This outputs a byte stream
            else:
                # TODO not tested on Linux
                proc = subprocess.Popen(['ping', '-c', packet_count, '-t', timeout, ip], stdout=subprocess.PIPE)
                output = proc.stdout.read()  # This outputs a byte stream

            if b"TTL" in output or b"ttl" in output:  # ...so it needs to be checked as such
                # Put IP on list if ping reached a host. The results will contain the TTL.
                results_q.put(ip)
        except:
            pass


"""
This function takes an argument of an IP (string format),
and strips the last octet to use the remainder as a net to scan.
E.g. supplying 192.168.1.1 will scan 192.168.1.0/24, or in other words
from 192.168.1.1 to 192.168.1.255.

Then it uses multithreading to perform a ping sweep.
Returns a list of active hosts.
"""


def ping_sweep(ip):
    start_time = time.time()
    pool_size = 51  # Number of threads
    # Default was 255 = 1 thread per address.
    # Kinda heavy, so instead it's 51 threads, 5 addresses each

    octets = ip.split('.')
    net_prefix = octets[0] + '.' + octets[1]+ '.' + octets[2]

    print('Scanning local network...')

    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    # Create pool_size of threads, put them in the pool
    pool = [multiprocessing.Process(target=pinger, args=(jobs, results))
                for i in range(pool_size)]

    # Start the threads
    for p in pool:
        p.start()

    # Add jobs (IPs) for the threads to do:
    for i in range(1, 255):  # This is the address range.
        jobs.put(net_prefix+'.{0}'.format(i))
        # This could be changed to scan in a wider range easily,
        # but that would require getting the subnet mask first,
        # which was too problematic to implement for the time.

    # Add None jobs to ensure threads terminate properly
    for p in pool:
        jobs.put(None)

    # This makes the function wait for all threads to finish
    for p in pool:
        p.join()

    # Copy the results:
    ip_list = []
    while not results.empty():
        ip_list.append(results.get())

    print('Ping sweep finished.')
    print("Scan duration: {} seconds".format(time.time() - start_time))
    return ip_list

# End ping sweep functions

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


# This is almost the same as ping_sweep. Check that function for comments
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
# Example: ['192.168.1.32', [21, 22, 23]]
# This isn't very efficient, but has to do for now...
def get_ports(ip, ip_ports):
    for entry in ip_ports:
        if ip in entry:
            return entry[1]


# End port scan functions

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

        # ip_list = ping_sweep(ipl)
        # TODO The scan takes too long for testing other things.
        #  Substitute with a direct list for now and remove it later
        ip_list = ['192.168.1.1', '192.168.1.27', '192.168.1.32']

        # TODO sort the IPs
        # print(ip_list)

        data_list = []
        open_ports_found = False
        ip_ports = scan_ports(ip_list)

        # Get host data
        for address in ip_list:
            host_data = socket.gethostbyaddr(address)
            # host_data structure is: (name, aliases, [IPs])
            ip_data = []
            ip_data.append(host_data[2][0])  # [0] First IP
            ip_data.append(host_data[0])  # [1] Name

            ports = get_ports(address,ip_ports)
            ip_data.append(ports)  # [2] Open ports (a list)
            #ip_data.append([])  # TODO This is a substitute to disable port scanning for testing; remove this

            data_list.append(ip_data)

        # Display hosts with found ports
        for entry in data_list:
            print("{}\t\t{}".format(entry[0], entry[1]))

            if len(entry[2]) != 0:
                open_ports_found = True
                print('├──This host has open ports:')
                for port in entry[2]:
                    print('├──{} ({})'.format(port, services.get(port)))

        if open_ports_found:
            print('Ports belonging to potentially dangerous services have been found on one or more of '
                  'the devices in your local network. Make sure to investigate and close or secure them.')
        else:
            print('No ports belonging to potentially dangerous services have been found.')

def main():
    # API loading is handled in the global scope on the top of the file.
    # print(api.info())

    # Test hosts:
    # ip = '24.158.43.67'  # Test host - vulnerable
    ip = '40.114.177.156 '  # Duckduckgo.com
    # ip = '8.8.8.8' # Test host - Google DNS

    print('\n----Service Checker----\n')

    while(True):
        print("\nWhat would you like to do?")
        command = input("Type:\n"
                        "1 to check your external IP on Shodan\n"
                        "2 to scan your local network\n"
                        "3 to create alerts for your local network\n"
                        "q to exit\n")
        if command == 'q':
            quit()
        elif command == '1':
            # Get router IP
            # ipify is open source and free; no visitor information is logged.
            # ip = get('https://api.ipify.org').text # TODO uncomment for final release
            print('\nYour public IP address is: {}'.format(ip))
            check_shodan(ip)
        elif command == '2':
            print('\nThe tool will now scan your local network for hosts and chosen opened ports.')
            # TODO give the choice to add shodan ports?
            #input("\nPress Enter to continue...")
            local_scan()
        elif command == '3':
            pass
        else:
            print('Wrong command.')




if __name__ == "__main__":
    main()
