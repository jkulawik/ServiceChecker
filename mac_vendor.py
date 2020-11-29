
from requests import get
import time
import config


def get_str(mac_address):
    if config.limit_vendor_requests:
        time.sleep(0.501)  # This had to be done to not be rate-limited

    # Truncate address for security reasons
    vendor_string = mac_address[0:8]

    # An API is used to get the vendor details
    url = "https://api.macvendors.com/"

    # Use get method to fetch details
    response = get(url + vendor_string).text

    #E.g: {"errors":{"detail":"Too Many Requests","message":"Please slow down...etc"}}
    err1 = 'Too Many Requests'
    err2 = 'Not Found'
    if err1 in response:
        return 'Error: ' + err1
    elif err2 in response:
        return err2
    elif 'errors' in response:
        return 'Unknown Error'
    else:
        if config.truncate_vendors:
            if len(response) > 30:
                response = response[0:29]
                response += '-'
        return response
