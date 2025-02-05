# Digital Certificates and VPN Lab

## Overview
This repository contains the configuration files and instructions for setting up a VPN with IPsec, certificates, and firewall rules as part of a cybersecurity lab. The objective is to:

1. **Configure Server A as a Certification Authority (CA)** using OpenSSL.
2. **Set up a transport mode IPsec VPN** with pre-shared key (PSK) authentication between Server A and Server B.
3. **Modify the VPN to use certificate-based authentication** signed by the CA created in Step 1.
4. **Change the VPN to tunnel mode** to protect communication between Site A and Site B, involving both Server A, Server B, Client A, and Client B.
5. **Configure firewalls** using `iptables` to secure the VPN and ensure that traffic between the sites is carried over the VPN tunnel.

## Prerequisites
Before setting up the VPN, ensure you have the following software installed:

- OpenSSL
- IPsec tools (such as `strongSwan` or `Libreswan`)
- Apache (for testing SSL certificates)
- `iptables` for configuring firewalls

## Setup Instructions

### 1. Configuring the Certification Authority (CA)
To set up Server A as a CA:

1. Navigate to the `Server A` directory.
2. Generate the private RSA key for both the root and CA1, as well as the public key:
   ```bash
   openssl genrsa -aes256 -out private/root.key.pem 4096
   openssl genrsa -aes256 -out ca1/private/ca1.key.pem 4096
   openssl rsa -in private/root.key.pem -pubout -out root.pub.pem
