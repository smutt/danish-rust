#!/usr/bin/env python3

# Copyright (c) 2019, Andrew McConachie <andrew@depht.com>
# All rights reserved.

import sys
import signal
import threading
import random
import urllib.request
import time

#############
# CONSTANTS #
#############

DYING = False # Set to True when a kill signal has been received
HTTP_TIMEOUT = 10 # Timeout for each HTTP GET in seconds
DELAY = 1 # Delay in seconds between each thread launch
SLEEP_CYCLE = 30 # How many seconds we sleep between each top-level iteration 
MAX_THREADS = 50 # Maximum number of threads permitted to be active

###########
# CLASSES #
###########

class UrlThr(threading.Thread):
  def __init__(self, site):
    self.site = site
    threading.Thread.__init__(self, name=type(self).__name__ + '_' + self.site)

  def run(self):
    try:
      urllib.request.urlopen("https://" + self.site + "/", timeout=HTTP_TIMEOUT)

    except urllib.error.URLError as e:
      print("UrlErr opening " + self.site)
      pass
    except urllib.error.HTTPError:
      print("HTTPErr opening " + self.site)
      pass
    except:
      print("Err general " + self.site)
      pass
    else:
      print("Success opening " + self.site)

####################
# GLOBAL FUNCTIONS #
####################

# Die gracefully
def euthanize(signal, frame):
  print("SIG-" + str(signal) + " exiting, gimme " + str(HTTP_TIMEOUT) + " seconds")

  # Set global dying flag
  global DYING
  DYING = True
  
  # Kill all timer threads
  for thr in threading.enumerate():
    if isinstance(thr, UrlThr):
      try:
        thr.cancel()
      except:
        pass

  sys.exit(0)


###################
# BEGIN EXECUTION #
###################

signal.signal(signal.SIGINT, euthanize)
signal.signal(signal.SIGTERM, euthanize)
signal.signal(signal.SIGABRT, euthanize)
signal.signal(signal.SIGALRM, euthanize)
signal.signal(signal.SIGSEGV, euthanize)
signal.signal(signal.SIGHUP, euthanize)

random.seed()
sites = []
with open('test-sites.txt', 'r') as f:
  for line in f.read().split('\n'):
   if len(line) > 0:
     if line[0] != '#':
       sites.append(line.strip('\n'))
f.closed

while True:
  if DYING:
    break

  activeThreads = 0
  for thr in threading.enumerate():
    if isinstance(thr, UrlThr):
      activeThreads += 1
  if activeThreads > MAX_THREADS:
    continue

  random.shuffle(sites)
  for st in sites:
    if DYING:
      break
    time.sleep(DELAY)
    UrlThr(st).start()
  time.sleep(SLEEP_CYCLE)

exit(0)
