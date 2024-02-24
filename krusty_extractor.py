#!/usr/bin/env python3
#
# krusty_extractor.py
# Copyright (C) 2024 - Synacktiv, Théo Letailleur
# contact@synacktiv.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Authors: Théo Letailleur (Synacktiv), Mohammad Kazem Hassan Nejad (WithSecure)
 
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from binascii import unhexlify
import sys


def xor(a,b):
    return bytes([x^b for x in a])

if len(sys.argv) < 2:
    print("usage: python crusty_decrypto.py ./sample")
    exit()

sample = sys.argv[1]

with open(sample, "rb") as sampleH:
    data = sampleH.read()

# Quick and dirty check for PE/ELF file sig
if data[0:2] == b'MZ':
    temp_path = b'c:/windows/temp/'
elif data[1:4] == b'ELF':
    temp_path = b'/tmp/'
else:
    print('File type check failed. Make sure the input is a PE or ELF file.')
    exit()

h = SHA256.new()
h.update(data)

print(f"Sample SHA256sum: {h.hexdigest()}")

end = data.find(b"|||||||||||||||||")
start = end - 0x100
start = start + data[start:end].find(temp_path) + len(temp_path)
ENCRYPTED =  unhexlify(data[start:end])
# 40 80 f5 XX == xor bpl, XX
before_xorkey = data.find(bytes.fromhex("FFFF4080F5"))
XORKEY = data[before_xorkey+len(bytes.fromhex("FFFF4080F5"))]
print(f"XOR KEY: {hex(XORKEY)}")
encrypted_stage2 = xor(ENCRYPTED, XORKEY)

start = start - len(temp_path) - 32
AESKEY = data[start:start+16]

start += 16
AESIV = data[start:start+16]

SEGMENT_SIZE = 128

print(f"AES-128 CFB KEY: {AESKEY.hex()}")
print(f"AES-128 CFB IV: {AESIV.hex()}")
cipher = AES.new(AESKEY, AES.MODE_CFB, iv=AESIV, segment_size=SEGMENT_SIZE)
decrypted = cipher.decrypt(encrypted_stage2)
print(f"Decrypted Stage Hoster URL: {decrypted.decode('utf-8')}")
