
from shodan import Shodan
from os import path
import textwrap

# Initialisations

api_file = "shodan_api_key.txt"
log_file = 'Vulnerabilities.txt'

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


def log(message):
    with open(log_file, 'a') as file:
        file.write(message + '\n')


# Check log for a string
def chk_log(message):
    with open(log_file, 'r') as file:
        whitelist = file.read()
    return message in whitelist


# The main function of the file
# Returns open ports
def check_shodan(ip):
    if not path.exists(api_file):
        open(api_file, "w+")
        print('Shodan API key file could not be found. Creating a new one.\n'
              'Paste your key inside if you wish to use the Shodan check and try again.')
        return

    file = open(api_file, "r")
    API_KEY = file.read(32)
    file.close()
    api = Shodan(API_KEY)

    # print(api.info())
    print('\nYour public IP address is: {}'.format(ip))

    try:
        ipinfo = api.host(ip)

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
        input("\nPress Enter to display full scan data...\n")

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
                for vuln in vulns:
                    key = str(vuln)
                    print('│\t\t├──Vulnerability: {}'.format(key))

                    if not chk_log(key):
                        vuln_data = vulns[key]
                        score = vuln_data['cvss']

                        print('│\t\t│\t├──Unregistered vulnerability. Printing more information to log file.')
                        print('│\t\t│\t├──Severity score (CVSS standard): {}/10'.format(score))
                        print('│\t\t│\t├──{}'.format(get_cvss_severity(score)))

                        log('\n' + '='*70 + '\nVulnerability: {}'.format(key))
                        log('Severity score (CVSS standard): {}/10'.format(score))
                        log(get_cvss_severity(score))
                        log('\nSummary:')
                        txt = textwrap.wrap(vuln_data['summary'], width=70)
                        for line in txt:
                            log(line)
                        log('\nReferences:')
                        for link in vuln_data['references']:
                            log(link)
                    else:
                        print('│\t\t│\t├──Vulnerability data already in log file.')
        return ipinfo["ports"]

    except Exception as exc:
        info = exc.__dict__
        if info["value"] == "No information available for that IP.":
            print(info["value"])
            print('That most likely means that your network is safe (not available from the Internet).')
        else:
            print("Exception", exc.__class__, "occurred.")
            print(info["value"])

# END SHODAN SEARCH FUNCTION
