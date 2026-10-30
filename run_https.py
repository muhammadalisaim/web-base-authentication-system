#!/usr/bin/env python3
"""
Convenience launcher to run Web Base Authentication System over HTTPS (Port 8443)
with SSL certificate and full encryption, eliminating browser 'Not Secure' warnings.
"""
import sys
import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

if __name__ == "__main__":
    from generate_ssl import generate_ssl_certificates
    generate_ssl_certificates(output_dir=BASE_DIR)

    from server import start_server
    print("[*] Starting Secure HTTPS Web Base Authentication System on Port 8443...")
    start_server(port=8443, bind="0.0.0.0", use_ssl=True)
