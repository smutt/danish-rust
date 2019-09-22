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
def get_certs(host, port=443):
  bad_host = False
  context = ssl.create_default_context()
  context.verify_mode = ssl.CERT_REQUIRED
  context.check_hostname = True
  conn = socket.create_connection((host, port))
  sock = context.wrap_socket(conn, server_hostname=host)
  sock.settimeout(HTTPS_TIMEOUT)

  try:
    der_cert = sock.getpeercert(True)
  except:
    bad_host = True
  finally:
    sock.close()

  if bad_host:
    return False
  else:
    #return ssl.DER_cert_to_PEM_cert(der_cert)
    return [der_cert]

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
      toks = str(rr).strip('.').split(' ')
      rec = {}
      rec['usage'] = int(toks[0])
      rec['selector'] = int(toks[1])
      rec['mtype'] = int(toks[2])
      rec['data'] = toks[3].lower()
      rv.append(rec)
    return rv

def dummy(x):
  return x

def validate(certs, tlsa_rrs, verbose=False):
  mTypes = {
    0: dummy,
    1: hashlib.sha256,
    2: hashlib.sha512
  }

  for tlsa in tlsa_rrs:
    if tlsa['selector'] == 1: # TODO: Implement this
      print("TLSA Selector 1 currently unsupported")
      exit(0)

    if tlsa['usage'] == 0: # PKIX-TA, won't work without whole chain
      if tlsa['data'] == mTypes[tlsa['mtype']](certs[0]).digest().hex():
        return True
    elif tlsa['usage'] == 1: # PKIX-EE
      if tlsa['data'] == mTypes[tlsa['mtype']](certs[-1]).digest().hex():
        return True
    elif tlsa['usage'] == 2: # DANE-TA, won't work without whole chain
      if tlsa['data'] == mTypes[tlsa['mtype']](certs[0]).digest().hex():
        return True
    elif tlsa['usage'] == 3: # DANE-EE
      if tlsa['data'] == mTypes[tlsa['mtype']](certs[-1]).digest().hex():
        return True

  return False

  
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
else:
  print("Failed fetching https://" + dom + "/index.html")

certs = get_certs(args.domain[0].strip())
if certs == False:
  print("No valid certificate found for " + dom)
  sys.exit(0)

tlsa_rrs = get_tlsa(args.domain[0].strip())
if tlsa_rrs:
  if args.verbose:
    print("TLSA RRs found for " + dom)
    for rr in tlsa_rrs:
      print(rr)
  if validate(certs, tlsa_rrs):
    print("Valid TLSA for " + dom)
  else:
    print("No valid TLSA for " + dom)

else:
  print("No TLSA for " + dom)


sys.exit(0)
