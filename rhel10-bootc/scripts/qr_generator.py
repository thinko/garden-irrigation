#!/usr/bin/env python3
"""
Garden-Tiller QR Code Generator
Generates a sequence of QR codes from data piped to stdin
"""

import sys
import qrcode
import gzip
import base64

def generate_qr_codes(data: bytes, chunk_size: int = 2048):
    """Generate a sequence of QR codes from data."""
    compressed_data = gzip.compress(data)
    encoded_data = base64.b64encode(compressed_data).decode("utf-8")

    chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]

    for i, chunk in enumerate(chunks):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(f"{i+1}/{len(chunks)}:{chunk}")
        qr.make(fit=True)
        qr.print_ascii(tty=True)

def main():
    """Main function."""
    data = sys.stdin.read().encode("utf-8")
    generate_qr_codes(data)

if __name__ == "__main__":
    main()
