#!/usr/bin/env python3

# Copyright (c) 2019, Andrew McConachie <andrew@depht.com>
# All rights reserved.

import sys
import os
import urllib.request
import argparse
import socket
import dns.resolver
import hashlib
from Crypto.Util.asn1 import DerSequence
from OpenSSL import SSL
from OpenSSL import crypto

###########
# CLASSES #
###########
class Dummy: # A class full of dummies
  def __init__(self, y):
    self.x = y

  def dummy(self):
    return self.x

  def hexdigest(self):
    return ''.join([hex(byte).split('0x')[1] for byte in self.x])

#############
# CONSTANTS #
#############
HTTPS_TIMEOUT = 10 # Timeout in seconds for HTTPS GET
MTYPES = { # Possible RFC 6698 matching types
  0: Dummy,
  1: hashlib.sha256,
  2: hashlib.sha512
}

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

# https://stackoverflow.com/questions/51039393/get-or-build-pem-certificate-chain-in-python
# TODO: Need to return the whole certificate chain and not just one
def get_certs(host, port=443):
  certs = []
  try:
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    sock = socket.create_connection((host, port))
    tls = SSL.Connection(ctx, sock)
    tls.set_connect_state()
    tls.set_tlsext_host_name(host.encode())
    tls.sendall(b'HEAD / HTTP/1.0\n\n')
    while tls.get_peer_finished() == None or tls.get_finished() == None:
      pass

    certs = tls.get_peer_cert_chain()
  except:
    sock.close()
    return certs
  finally:
    sock.close()

  return [crypto.dump_certificate(crypto.FILETYPE_ASN1, cert) for cert in certs]

def get_a(host):
  d = dns.resolver.Resolver()
  try:
    resp = d.query(host, 'A')
  except:
    return False

  if len(resp.rrset) < 1:
    return False
  else:
    return resp.rrset[0]

def get_aaaa(host):
  d = dns.resolver.Resolver()
  try:
    resp = d.query(host, 'AAAA')
  except:
    return False

  if len(resp.rrset) < 1:
    return False
  else:
    return resp.rrset[0]

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

# https://stackoverflow.com/questions/12911373/how-do-i-use-a-x509-certificate-with-pycrypto
def extract_pub_key(der):
  cert = DerSequence()
  cert.decode(der)
  tbsCertificate = DerSequence()
  tbsCertificate.decode(cert[0])
  if args.very_verbose:
    ss = ''
    for byte in tbsCertificate[6]:
      ss += str(byte) + ' '
    print("FULL SPKI")
    print("[ " + ss + "]")

  return tbsCertificate[6]

def validate(certs, tlsa_rrs, verbose=False):
  for tlsa in tlsa_rrs:
    if tlsa['usage'] == 0 or tlsa['usage'] == 2: # Trust Anchor
      if tlsa['selector'] == 0:
        if tlsa['data'] == MTYPES[tlsa['mtype']](certs[-1]).hexdigest():
          return True
      else:
        pub_key = extract_pub_key(certs[-1])
        if tlsa['data'] == MTYPES[tlsa['mtype']](pub_key).hexdigest():
          return True

    elif tlsa['usage'] == 1 or tlsa['usage'] == 3: # End Entity
      if tlsa['selector'] == 0:
        if tlsa['data'] == MTYPES[tlsa['mtype']](certs[0]).hexdigest():
          return True
      else:
        pub_key = extract_pub_key(certs[0])
        if tlsa['data'] == MTYPES[tlsa['mtype']](pub_key).hexdigest():
          return True

  return False

def printSpki(certs):
  for cert in certs:
    components = crypto.load_certificate(crypto.FILETYPE_ASN1, cert).get_subject().get_components()
    print(' '.join([entity.decode('UTF-8') + '=' + name.decode('UTF-8') for entity,name in components]))

    derSeq = DerSequence()
    derSeq.decode(cert)
    tbsCert = DerSequence()
    tbsCert.decode(derSeq[0])

    if args.hash == 'none':
      print("\t" + MTYPES[0](extract_pub_key(cert)).hexdigest())
    elif args.hash == 'sha256':
      print("\t" + MTYPES[1](extract_pub_key(cert)).hexdigest())
    elif args.hash == 'sha512':
      print("\t" + MTYPES[2](extract_pub_key(cert)).hexdigest())

###################
# BEGIN EXECUTION #
###################

ap = argparse.ArgumentParser(description='Test HTTPS DANE validation for a domain')
ap.add_argument('domain', nargs=1, help='Domain under test')
ap.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Verbose output')
ap.add_argument('-vv', '--very_verbose', action='store_true', dest='very_verbose', help='Very Verbose output')
ap.add_argument('-s', '--spki', action='store_true', dest='spki', help='Print hash of SubjectPublicKeyInfo for each certificate')
ap.add_argument('-ha', '--hash', dest='hash', default='sha256', choices=['none', 'sha256', 'sha512'], help='Hash algorithm to use for SPKI, default:sha256')
args = ap.parse_args()

if args.very_verbose:
  args.verbose = True

dom = args.domain[0].strip()

if get_a(dom) or get_aaaa(dom):
  if args.verbose:
    print("Success fetching A/AAAA for " + dom)
else:
  print("Bad Domain " + dom)
  sys.exit(1)

if fetch_index(dom):
  if args.verbose:
    print("Success fetching https://" + dom + "/index.html")
else:
  print("Failed fetching https://" + dom + "/index.html")

if args.verbose:
  print("Fetching certificate chain for " + dom)
certs = get_certs(dom)

if len(certs) == 0:
  print("No certificates found for " + dom)
  sys.exit(0)

if args.spki:
  printSpki(certs)

tlsa_rrs = get_tlsa(dom)
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
