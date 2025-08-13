#!/usr/bin/env python3
"""
Garden-Tiller Data Exporter Script
Exports data to various destinations
"""

import json
import argparse
import os
import sys
from typing import Dict, Any
import ftplib
import pysftp
import tftpy


def export_data(data: Dict[str, Any], destination: str, **kwargs):
    """Export data to a destination."""
    if destination == "tftp":
        export_tftp(data, **kwargs)
    elif destination == "ftp":
        export_ftp(data, **kwargs)
    elif destination == "sftp":
        export_sftp(data, **kwargs)
    else:
        raise ValueError(f"Unknown destination: {destination}")

def export_tftp(data: Dict[str, Any], host: str, port: int = 69, filename: str = "data.json"):
    """Export data to a TFTP server."""
    client = tftpy.TftpClient(host, port)
    with open(filename, "w") as f:
        json.dump(data, f)
    client.upload(filename, filename)

def export_ftp(data: Dict[str, Any], host: str, user: str, passwd: str, filename: str = "data.json"):
    """Export data to an FTP server."""
    with ftplib.FTP(host, user, passwd) as ftp:
        with open(filename, "w") as f:
            json.dump(data, f)
        with open(filename, "rb") as f:
            ftp.storbinary(f"STOR {filename}", f)

def export_sftp(data: Dict[str, Any], host: str, user: str, passwd: str, filename: str = "data.json"):
    """Export data to an SFTP server."""
    with pysftp.Connection(host, username=user, password=passwd) as sftp:
        with open(filename, "w") as f:
            json.dump(data, f)
        sftp.put(filename)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Data Exporter")
    parser.add_argument("destination", choices=["tftp", "ftp", "sftp"], help="Destination type")
    parser.add_argument("--host", required=True, help="Destination host")
    parser.add_argument("--port", type=int, help="Destination port")
    parser.add_argument("--user", help="Username for FTP/SFTP")
    parser.add_argument("--password", help="Password for FTP/SFTP")
    parser.add_argument("--file", required=True, help="JSON file to export")
    parser.add_argument("--filename", help="Remote filename")

    args = parser.parse_args()

    with open(args.file, "r") as f:
        data = json.load(f)

    kwargs = {
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "passwd": args.password,
        "filename": args.filename or os.path.basename(args.file),
    }

    try:
        export_data(data, args.destination, **kwargs)
        print(f"Successfully exported data to {args.destination}://{args.host}")
    except Exception as e:
        print(f"Failed to export data: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
