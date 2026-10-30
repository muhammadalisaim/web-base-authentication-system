#!/usr/bin/env python3
"""
SSL Certificate Generator for Web Base Authentication System
Generates self-signed SSL certificate (ssl_cert.pem) and private key (ssl_key.pem)
with Subject Alternative Names (SAN) for localhost, 127.0.0.1, and local LAN IPs.
"""
import os
import subprocess
import sys
import socket

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.10.69.195"

def generate_ssl_certificates(output_dir=".", days=365):
    cert_path = os.path.join(output_dir, "ssl_cert.pem")
    key_path = os.path.join(output_dir, "ssl_key.pem")
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print(f"[*] SSL certificate already exists: {cert_path}")
        return cert_path, key_path
    
    lan_ip = get_lan_ip()
    print(f"[*] Generating SSL certificate for localhost and LAN IP: {lan_ip}")

    # Generate OpenSSL config with SAN
    cnf_content = f"""[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = PK
ST = Punjab
L = Bahawalpur
O = The Islamia University of Bahawalpur
OU = CAIPSD Cybersecurity Division
CN = Web Base Authentication System

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = *.local
DNS.3 = iub.edu.pk
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
IP.3 = {lan_ip}
"""
    cnf_file = os.path.join(output_dir, "openssl_san.cnf")
    with open(cnf_file, "w") as f:
        f.write(cnf_content)

    try:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", cert_path,
            "-days", str(days),
            "-nodes",
            "-config", cnf_file
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] SSL Certificate generated successfully!")
        print(f"    Certificate: {cert_path}")
        print(f"    Private Key: {key_path}")
        if os.path.exists(cnf_file):
            os.remove(cnf_file)
        return cert_path, key_path
    except Exception as e:
        print(f"[-] OpenSSL command failed: {e}")
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime
            import ipaddress

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Bahawalpur"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Islamia University of Bahawalpur"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Web Base Authentication System"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                        x509.IPAddress(ipaddress.IPv4Address(lan_ip))
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            print(f"[+] Python Cryptography SSL generated successfully!")
            return cert_path, key_path
        except Exception as py_e:
            print(f"[-] Fallback generator failed: {py_e}")
            return None, None

if __name__ == "__main__":
    generate_ssl_certificates()
