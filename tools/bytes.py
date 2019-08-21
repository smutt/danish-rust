#!/usr/bin/python

import sys
import os
import re
import fileinput

# Rust code to produce debug output. Send to stdin of this script.
# debug!("hex {:?}", payload.iter().map(|h| format!("{:X}", h)).collect::<Vec<_>>());

# Takes a list of character nibbles
# Prints them in pretty nibble hex format
def printNibbles(chars):
  ii = 1
  outStr = "0000 | "
  outAsc = ""
  for c in chars:
    if len(c) == 1:
      c = "0" + c
    outStr += c + " "
    if(int(c, 16) > 32 and int(c, 16) < 127):
      outAsc += chr(int(c, 16))
    else:
      outAsc += "."

    if(ii % 4 == 0):
      outStr += "  "

    if(ii % 16 == 0):
      print(outStr + " | " + outAsc)
      outStr = format(ii, 'X').zfill(4) + " | "
      outAsc = ""
    ii += 1
  print(outStr)

for line in fileinput.input():
  if len(line.strip()) > 0:
    if line.find('hex [') != -1:
      s = line.replace("hex [", "")
      s = s.replace("]", "")
      s = s.replace("\"", "")
      s = s.replace("\n", "")
      toks = s.split(", ")
      printNibbles(toks)
      print("")

