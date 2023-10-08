#!/usr/bin/env python3

# Author: David Bolvansky
# Licence: MIT, see LICENSE

import argparse
import subprocess
import os
import sys
import binascii
import json
from typing import Optional, List

class HashIdentifier:
    def __init__(self, hash: str):
        self.hash = hash

    def getHashcatHashType(self) -> Optional[int]:
        hash_lower = self.hash.lower()
        # MS Office
        if hash_lower[1:10] == 'oldoffice':
            if hash_lower[11:12] == '0' or hash_lower[11:12] == '1':
                return 9700       # Office 97-2000 (MD5)
            else:
                return 9800       # Office 2003 (SHA1)
        elif hash_lower[1:7] == 'office':
            if hash_lower[9:13] == '2007':
                return 9400       # Office 2007 (AES + SHA1)
            elif hash_lower[9:13] == '2010':
                return 9500       # Office 2010 (SHA512)
            elif hash_lower[9:13] == '2013':
                return 9600       # Office 2013/16 (100k rounds)
        # PDF
        elif hash_lower[1:4] == 'pdf':
            if hash_lower[5] == '1':
                return 10400          # PDF 1.1 - 1.3 (Acrobat 2 - 4)
            elif (hash_lower[5] == '2' or
                hash_lower[5] == '3' or
                hash_lower[5] == '4'):
                return 10500          # PDF 1.4 - 1.6 (Acrobat 5 - 8)
            elif hash_lower[5:8] == '5*5':
                return 10600          # PDF 1.7 Level 3 (Acrobat 9)
            else:
                return 10700          # PDF 1.7 Level 8 (Acrobat 10 - 11)

        # RAR
        elif hash_lower[1:4] == 'rar':
            if hash_lower[4:8].lower() == '3$*0':
                return 12500          # RAR3-hp
            elif hash_lower[4]== '5':
                return 13000          # RAR5
            elif hash_lower[4:8] == '3$*1':
                try:
                    method = int(hash_lower[-2:])
                    if method == 30:
                        return 23700  # RAR3-p Uncompressed
                    elif 36 > method > 30:
                        return 23800  # RAR3-p Compressed
                except ValueError:
                    pass
        # ZIP
        elif hash_lower[1:4] == 'zip':
            if hash_lower[4] == '2':
                return 13600          # Win-Zip
            elif hash_lower[4] == '3':
                enc_type_pos = hash_lower.replace('*', 'X', 2).find('*') + 1
                enc_type = hash_lower[enc_type_pos:enc_type_pos + 3]
                if enc_type == '128':
                    return 23001      # SecureZIP AES-128
                elif enc_type == '192':
                    return 23002      # SecureZIP AES-192
                elif enc_type == '256':
                    return 23003      # SecureZIP AES-256
        # PKZIP
        elif hash_lower[1:6] == 'pkzip':
            if hash_lower[hash_lower.find('*') - 1] == '1':
                compression_type = hash_lower[hash_lower.replace('*', 'X', 8).find('*') + 1]
                if compression_type == '8':
                    return 17200  # PKZIP compressed
                else:
                    return 17210  # PKZIP uncompressed
            else:
                return 17225      # PKZIP Multifile Mixed
        # 7-Zip
        elif hash_lower[1:3] == '7z':
            return 11600
        
        # Bitcoin/Litecoin wallet.dat
        elif hash_lower[1:8] == 'bitcoin':
            return 11300

        # Ethereum Wallet
        elif hash_lower[1:9] == 'ethereum':
            if hash_lower[10] == 'p':
                return 15600 # Ethereum Wallet, PBKDF2-HMAC-SHA256
            elif hash_lower[10] == 's':
                return 15700 # Ethereum Wallet, SCRYPT
            elif hash_lower[10] == 'w':
                return 16300 # Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256

        # Exodus
        elif hash_lower[1:7] == 'exodus':
            return 16300

        # MetaMask
        elif hash_lower[1:9] == 'metamask':
            if hash_lower[1:15] == 'metamask-short':
                return 26610 # MetaMask Wallet (short hash, plaintext check)
            elif hash_lower[1:15] == 'metamaskMobile':
                return 31900 # MetaMask Mobile Wallet
            elif hash_lower[1:9] == 'metamask':
                return 26600 # MetaMask Wallet (needs all data, checks AES-GCM tag)

        # Electrum
        elif hash_lower[1:9] == 'electrum':
            if hash_lower[10] == '1':
                return 16600 # Electrum Wallet (Salt-Type 1-3)
            elif hash_lower[10] == '4':
                return 21700 # Electrum Wallet (Salt-Type 4)
            elif hash_lower[10] == '5':
                return 21800 # Electrum Wallet (Salt-Type 5)

        return None

class FileFormat:
    def __init__(self, id: int, extensions: List[str], signatures: List[bytes], extractor: str):
        self.id = id
        self.extensions = extensions
        self.signatures = signatures
        self.extractor = extractor

    def matchesSignature(self, signature: bytes) -> bool:
        if not self.signatures:
            return True

        for sig in self.signatures:
            if signature.startswith(sig):
                return True
        return False

    def matchesExtension(self, extension: str) -> bool:
        for ext in self.extensions:
            if extension.lower() == ext.lower():
                return True
        return False

    def extractHash(self, path: str) -> Optional[str]:
        result = subprocess.run([self.extractor, path], capture_output=True, text=True)
        out = result.stdout
        err = result.stderr

        if not out:
            return None
        else:
            hash_str = out

            if any(ext in ['.rar', '.zip', '.pdf', '.json', '.electrum'] for ext in self.extensions):
                parts = hash_str.split(':', 2)
                hash_str = parts[1] if len(parts) > 1 else parts[0]

            return hash_str.strip()


class HashExtractor:
    def __init__(self, path: str):
        self.path = path

        self.formats = []
        self.formats.append(FileFormat(0, ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'], [b'd0cf11e0a1b11ae1'], 'extractors/office2hashcat.py'))
        self.formats.append(FileFormat(1, ['.pdf'], [b'25504446'], 'extractors/pdf2john.pl'))
        self.formats.append(FileFormat(2, ['.rar'], [b'526172211a07'], 'extractors/rar2hashcat'))
        self.formats.append(FileFormat(3, ['.zip'], [b'504b0304'], 'extractors/zip2hashcat'))
        self.formats.append(FileFormat(4, ['.7z'], [b'377abcaf271c'], 'extractors/7z2hashcat.pl'))
        self.formats.append(FileFormat(5, ['.dat'], [], 'extractors/bitcoin2john.py'))
        self.formats.append(FileFormat(6, ['.json'], [], 'extractors/ethereum2john.py'))
        self.formats.append(FileFormat(7, ['.seco'], [], 'extractors/exodus2hashcat.py'))
        self.formats.append(FileFormat(8, ['.json'], [], 'extractors/metamask2hashcat.py'))
        self.formats.append(FileFormat(9, ['.electrum'], [], 'extractors/electrum2john.py'))
        self.formats.append(FileFormat(10, ['.ldb'], [], 'extractors/metamask_extractor'))

    def detectFileFormat(self) -> Optional[bool]:
        try:
            # Open the file, extract signature and extension
            f = open(self.path, 'rb')
            sig = f.read(20)
            sig = binascii.hexlify(sig)
            ext = os.path.splitext(self.path)[1]
        except OSError:
            sig = None
            ext = None

        # Custom match rules
        if self.path.endswith(".json"):
            with open(self.path, 'r') as json_file:
                json_data = json.load(json_file)
                required_keys = ['data', 'iv', 'salt']
                if all(key in json_data for key in required_keys):
                    return 8 # MetaMask

        for format in self.formats:
            if ext and format.matchesExtension(ext):
                if sig:
                    if format.matchesSignature(sig):
                        return format.id
                else:
                    return format.id

        return None

    def extractHash(self) -> Optional[str]:
        file_format = self.detectFileFormat()
        if not file_format:
            return None

        return self.formats[file_format].extractHash(self.path)

def main():
    parser = argparse.ArgumentParser(description="Extract the hash of a file")
    parser.add_argument("path", help="Path to the file")
    parser.add_argument("-t", "--print-hash-type", action='store_true', help="Print hash type")
    args = parser.parse_args()

    extractor = HashExtractor(args.path)

    extracted_hash = extractor.extractHash()
    if not extracted_hash:
        print("Unable to extract hash", file=sys.stderr)
        return 1

    print(extracted_hash)
    if args.print_hash_type:
        identifier = HashIdentifier(extracted_hash)
        hash_type = identifier.getHashcatHashType()
        if hash_type:
            print(hash_type)

    return 0


if __name__ == "__main__":
    exit(main())
