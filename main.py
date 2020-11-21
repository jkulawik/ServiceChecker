# Internet interaction imports
from shodan import Shodan
from requests import get

# Ping sweep imports
import multiprocessing
import subprocess

# Utilities
import platform
import socket # To query the LAN

# TODO make sure if putting an API key into the source code is a good idea
API_KEY = 'c107zh5Xn6ICqI4yqdP1nDvPTyEBEq51'
api = Shodan(API_KEY)

OP_SYS = platform.system()


# TODO Debug, can be deleted in final version
def print_type(arg):
    print("Data type: {}".format(type(arg)))


def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    return ip


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
        # pprint.pprint(ipinfo)  # TODO remove this later

        port_data = ipinfo["data"]  # Info per port

        # -------Summary-------

        port_count = len(port_data)
        print("Detected {} reachable ports.".format(port_count))
        if port_count > 0:
            print('Ports available from your IP are: {}'.format(ipinfo["ports"]))
            print('Make sure if exposing these services is desired.')
            print('If it is not, and  you are not accessing your device/network from outside, '
                  'it would be best to turn off those services.')
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
            print('No vulnerabilities detected.')

        # -------End of the summary-------

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


def pinger(job_q, results_q):
    while True:
        ip = job_q.get()
        if ip is None: break

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
    pool_size = 30  # Number of threads (default was 255)

    octets = ip.split('.')
    net_prefix =  octets[0] + '.' + octets[1]+ '.' + octets[2]

    print('Scanning local network...')

    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=pinger, args=(jobs, results))
                for i in range(pool_size)]

    for p in pool:
        p.start()

    # This is the address range.
    # It could be changed to scan in a wider range easily,
    # but that would require getting the subnet mask first, which proved to be very problematic.
    for i in range(1, 255):
        jobs.put(net_prefix+'.{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    ip_list = []
    while not results.empty():
        ip_list.append(results.get())

    print('Ping sweep finished.')
    return ip_list

# End ping sweep functions


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

# ip.split('.')


def main():
    # print(api.info())

    # Get router IP
    # ipify is open source and free; no visitor information is logged.
    ip = get('https://api.ipify.org').text

    # Test hosts:
    # ip = '24.158.43.67'  # Test host - vulnerable
    # ip = '40.114.177.156 ' # Duckduckgo.com
    # ip = '8.8.8.8' # Test host - Google DNS

    print('\nYour public IP address is: {}'.format(ip))

    # check_shodan(ip)

    ipl = get_lan_ip()  # Local IP
    print('\nYour local IP is: {}'.format(ipl))

    if ip_check_local(ipl) is False:
        print('Your address does not appear to be from a local network. Aborting scan.')
    else:
        print('Note: currently the program can only scan the addresses in the last IP octet range (like in a /24 '
              'subnet).')

        ip_list = ping_sweep(ipl)
        # TODO The scan takes too long for testing. Substitute with a direct list for now and remove it later
        #ip_list = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.10', '192.168.1.11', '192.168.1.27']

        # TODO sort the IPs
        print(ip_list)

        data_list = []
        # Get host names
        for address in ip_list:
            data_list.append(socket.gethostbyaddr(address))
        # ...and display them along their IPs
        for entry in data_list:
            print("{}\t\t{}".format(entry[2][0], entry[0]))


if __name__ == "__main__":
    main()
