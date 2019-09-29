#!/usr/bin/python -tt
# subdomain-hunter
# Originally made by https://crazybulletctfwriteups.wordpress.com/2018/01/18/subdomain-scanner-using-censys-python/
# Original author: P3t3rp4rk3r
# Modified by: compsecdirect
# Version: 0.2

import sys
import os
import time
import censys.certificates
import censys.ipv4
import censys

#finding the subdomains related to given domain
def subdomain_find(domain,start,censys_id,censys_secret):
    try:
        censys_cert = censys.certificates.CensysCertificates(api_id=censys_id,api_secret=censys_secret)
        cert_query = 'parsed.names: %s AND parsed.validity.start: %s' % (domain, start)
        #cert_query = 'parsed.names: %s'  % domain
        cert_search_results = censys_cert.search(cert_query, fields=['parsed.names', 'parsed.validity.start'])
        print cert_search_results
        subdomains = [] #List of subdomains
        for s in cert_search_results:
            subdomains.extend(s['parsed.names'])

        return set(subdomains) #removes duplicate values
    except censys.base.CensysUnauthorizedException:
        sys.stderr.write('[+] Censys account details wrong. \n')
        exit(1)
    except censys.base.CensysRateLimitExceededException:
        sys.stderr.write('[+] Limit exceeded.')
        exit(1)
def subdomain_filter(domain,subdomains): #If subdomain has *.domain.com It will filter out from list of subdomains.
    return [ subdomain for subdomain in subdomains if '*' not in subdomain and subdomain.endswith(domain) ]

def subdomains_list(domain, subdomains): #Take the list and showing structured way.
    if len(subdomains) is 0:
        print('[-] Did not find any subdomain')
        return

    print('[*] Found %d unique subdomain \n' % (len(subdomains)))
    for subdomain in subdomains:
        print(subdomain)

    print('')
def main(domain,start,censys_id,censys_secret):
    print ("[+] Finding the subdomains of %s " % domain)
    subdomains = subdomain_find(domain,start,censys_id,censys_secret)
    subdomains = subdomain_filter(domain,subdomains)
    subdomains_list(domain,subdomains)

if __name__ == "__main__":
    censys_id = ""
    censys_secret = ""
    domain = raw_input("Enter the domain:")
    start= raw_input("Enter the start time with range ex: [2000-01 TO 2017-07-31]:")
    main(domain,start,censys_id,censys_secret)
