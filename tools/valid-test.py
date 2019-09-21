#!/usr/bin/env python3

# Copyright (c) 2019, Andrew McConachie <andrew@depht.com>
# All rights reserved.

import sys
#import random
import urllib.request
#import time
import argparse
import ssl
import socket
#import OpenSSL
import dns.resolver
import hashlib

#############
# CONSTANTS #
#############

HTTPS_TIMEOUT = 10 # Timeout for each HTTP GET in seconds

####################
# GLOBAL FUNCTIONS #
####################

def fetch_index(host):
  try:
    urllib.request.urlopen("https://" + host + "/index.html", timeout=HTTPS_TIMEOUT)

  except urllib.error.URLError as e:
    return False
    pass
  except urllib.error.HTTPError:
    return False
    pass
  except:
    return False
    pass
  else:
    return True

# https://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python
# TODO: Need to return the whole certificate chain and not just one
def get_cert(host, port=443):
  context = ssl.create_default_context()
  conn = socket.create_connection((host, port))
  sock = context.wrap_socket(conn, server_hostname=host)
  sock.settimeout(HTTPS_TIMEOUT)

  try:
    der_cert = sock.getpeercert(True)
  finally:
    sock.close()
  #return ssl.DER_cert_to_PEM_cert(der_cert)
  return der_cert

def get_tlsa(host, port=443, trans='tcp'):
  d = dns.resolver.Resolver()
  try:
    resp = d.query("_" + str(port) + "._" + trans + "." + host, 'TLSA')
  except:
    return False

  if len(resp.rrset) < 1:
      return False
  else:
    rv = []
    for rr in resp.rrset:
      rv.append(str(rr).strip('.'))
    return rv
    #return str(resp.rrset[0]).strip('.')
    
def validate(cert, tlsa, verbose=False):
  mTypes = {
    1: hashlib.sha256,
    2: hashlib.sha512
  }
  return True

  
###################
# BEGIN EXECUTION #
###################

ap = argparse.ArgumentParser(description='Test HTTPS DANE validation for a domain')
ap.add_argument('domain', nargs=1, help='Domain under test')
ap.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Verbose operation')
args = ap.parse_args()

dom = args.domain[0].strip()

if fetch_index(dom):
  if args.verbose:
    print("Success fetching https://" + dom + "/index.html")
  
  cert = get_cert(args.domain[0].strip())
  tlsa_rrs = get_tlsa(args.domain[0].strip())
  if tlsa_rrs:
    if args.verbose:
      print("TLSA RRs found for " + dom)
      for rr in tlsa_rrs:
        print(rr)
    if validate(cert, tlsa_rrs):
      print("Valid TLSA for " + dom)
    else:
      print("No valid TLSA for " + dom)

  else:
    print("No TLSA for " + dom)

else:
  print("Failed fetching https://" + dom + "/index.html")
  
sys.exit(0)
