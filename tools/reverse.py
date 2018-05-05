#!/usr/bin/env python
""" Print out a string in 'PUSH order' for use in shellcodes.
"""
import sys

if len(sys.argv) != 2:
    print('Usage: %s <string_to_reverse>' % sys.argv[0])
    raise SystemExit

instr = sys.argv[1]
strlen = len(instr)
print('[+] String Length: %s' % strlen)

output = dict()

lenmod = strlen % 4

if lenmod != 0:
    pad = lenmod
    if lenmod == 1:
        pad = 3
    if lenmod == 3:
        pad = 1
    print('[-] WARN: String length is not a multiple of four, padding with %s \\x41' % pad)

    instr = ('A' * pad) + instr

rev = instr[::-1]

for i in (range(len(instr), 0, -4)):
    try:
        convstr = instr[i-4:i][::-1]
        print('%s : %s' % (convstr, ('0x'+convstr.encode('hex'))))
    except:
        continue

