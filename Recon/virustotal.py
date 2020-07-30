from __future__ import print_function


__author__ = "Bharath"
__version__ = "0.1.0"
__description__ = "A script to extract sub-domains that virus total \
                   has found for a given domain name"
import sys

try:
    from requests import get, exceptions
except ImportError:
    raise ImportError('requests library missing. pip install requests')
    sys.exit(1)

def get_domain():
    if len(sys.argv) <= 1:
        print("\n\033[33mUsage: python virustotal_enum.py <domain> \033[1;m\n")
        sys.exit(1)
    else:
        return sys.argv[1]

def check_virustotal(domain_name=None, url=None):
    if url is None:
        url = "https://www.virustotal.com/ui/domains/{0}/subdomains?limit=40".format(domain_name)
    try:
        req = get(url)
    except exceptions.RequestException as e:  # This is the correct syntax
        print(e)
        sys.exit(1)
    response = get(url)
    return response.json()

def print_results(search_results):
    for index, item in enumerate(search_results['data']):
        print(item['id'])
        if 'last_https_certificate' in item['attributes'].keys():
            for index,item in enumerate(item['attributes']['last_https_certificate']['extensions']['subject_alternative_name']):
                print(item)
    

if __name__ == '__main__':
    domain_name = get_domain()

    search_results = check_virustotal(domain_name)
    while True:
        print_results(search_results)
        if 'next' in search_results['links'].keys():
            next_url = search_results['links']['next']
            search_results = check_virustotal(url=next_url)
        else:
            break