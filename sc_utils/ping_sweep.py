
# Ping sweep utility
# The main function is get_ip_list(ip) which returns a list of active IPs.
# Currently it assumes a /24 mask on the IP.
# E.g. supplying 192.168.1.1 will scan 192.168.1.0/24, or in other words
# from 192.168.1.1 to 192.168.1.255.
# IP must be supplied in string format.

import subprocess
import multiprocessing
import time
import platform
import config

# Init
OP_SYS = platform.system()


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

Then it uses multi-threading to perform a ping sweep.
Returns a list of active hosts.
"""


def get_ip_list(ip):
    start_time = time.time()
    pool_size = config.ping_threads  # Number of threads
    # Default was 255 = 1 thread per address.
    # Fewer threads turns out to be faster

    octets = ip.split('.')
    net_prefix = octets[0] + '.' + octets[1] + '.' + octets[2]

    print('Scanning local network. This might take a minute...')

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
