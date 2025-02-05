# Digital Certificates and VPN Lab


## Overview
This repository contains Lab 2 of the Network and System Security course at Blekinge Institute of Technology, Sweden and it is a continuation of the [Firewall-Config-Lab](https://github.com/patteeraL/Firewall-Config-Lab.git) and contains the configuration files and instructions for setting up a VPN with IPsec, certificates, and firewall rules as part of a cybersecurity lab. 

The objective is to:

1. **Configure Server A as a Certification Authority (CA)** using OpenSSL.
2. **Set up a transport mode IPsec VPN** with pre-shared key (PSK) authentication between Server A and Server B.
3. **Modify the VPN to use certificate-based authentication** signed by the CA created in Step 1.
4. **Change the VPN to tunnel mode** to protect communication between Site A and Site B, involving Server A, Server B, Client A, and Client B.
5. **Configure firewalls** using `iptables` to secure the VPN and ensure that traffic between the sites is routed over the VPN tunnel.

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
 3. Generate the self-signed root certificate:
   ```bash
   openssl req -config openssl.cnf -key private/root.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/root.cert.pem
   ```
 4. Create a certificate signing request (CSR) for the intermediate CA (CA1):
   ```bash
openssl req -config ca1/openssl.cnf -new -sha256 -key ca1/private/ca1.key.pem -out ca1/csr/ca1.csr.pem
   ```
 5. Sign the CSR with the root certificate:
   ```bash
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in ca1/csr/ca1.csr.pem -out ca1/certs/ca1.cert.pem
   ```
 6. Verify the CA1 certificate:
   ```bash
openssl verify -CAfile certs/root.cert.pem ca1/certs/ca1.cert.pem
   ```
 7. Create a certificate chain file containing both intermediate CA and the root CA certificate:
   ```bash
cat ca1/certs/ca1.cert.pem certs/root.cert.pem > ca1/certs/ca1.cert-chain.pem
   ```
 8. Create and sign a server certificate. Perform the same steps as before for the server and sign the server CSR with CA1’s private key. Lastly, verify the server certificate against the certificate chain using OpenSSL.
    
### 2. Configure Apache Web Server to Use the Server Certificate
 1. Copy the server’s private key to the folder ```/etc/ssl/private/``` and the certificate to ```/etc/ssl/certs/```.
 2. Create the directory /ssl.crt and copy the certificate chain file to the directory:
   ```bash
sudo cp ca1/certs/ca1.cert-chain.pem /etc/apache2/ssl.crt/
   ```
 3. Open the file    ``` /etc/apache2/sites-enabled/default-ssl.conf ``` using nano and replace the correct paths to the SSL certificate and key.
 4. Finally, restart Apache to apply the changes:
   ```bash
sudo service apache2 restart
   ```
### 3. Add the Certificate Chain to Firefox Web Browser
 1. Edit the file ca1/openssl.cnf and add the line copy_extensions = copy in the [CA_default] section.
 2. Start the Firefox browser on Server A and enter ```https://localhost``` in the URL field.
 3. Select ‘Menu’ > ‘Settings’ > ‘Privacy & Security’ > ‘View Certificates’.
 4. Open the ‘Certificate Manager’ and select ‘Authorities’.
 5. Click ‘Import’ and select the certificate chain.
 6. Generate a CSR for the server:
   ```bash
openssl req -config ca1/openssl.cnf -addext "subjectAltName = DNS:localhost" -new -sha256 -key ca1/private/server.key.pem -out ca1/csr/sc2.csr.pem
   ```
 7. Generate the certificate from the CSR and proceed with the next steps.
 8. Copy ```sc2.cert.pem``` to ```/etc/ssl/certs/``` and replace the correct paths to the SSL certificate and key in ```/etc/apache2/sites-enabled/default-ssl.conf``` using nano.
 9. Finally, browse ```https://localhost``` again. You should see the padlock indicating a secure connection. Click on 'More Information' > 'View Certificate' to view the certificate details.
### 4. strongSwan IPsec VPN
 1. List the policies in the RPDB by entering the following command:
   ```bash
ip rule show
   ```
 2. To list the available routes in a table (e.g., local), use:
   ```bash
ip route list table local
   ```
### 5. Installing and Configuring strongSwan
 1. Begin by installing strongSwan on Server A and Server B:
   ```bash
sudo apt-get install strongswan
   ```
 2. Reboot the VMs after installation to ensure all services are started.
### 6. Host-to-Host Transport Mode VPN with PSK Authentication
 1. Configure Server A and Server B to establish a host-to-host transport VPN using PSK and IKEv2. Use nano to set the password "your-password" in ```/etc/ipsec.secrets``` and configure ```auto = route``` in ```/etc/ipsec.conf```.
 2. Verify the setup by starting Wireshark on Server A and Server B, then ping the IP address of Server B on the public network:
   ```bash
ping 192.168.70.6
   ```
 3. Check the established connections on Server A:
   ```bash
sudo ipsec statusall
   ```
### 7. Decrypt Traffic with Wireshark
To extract the SPI numbers, encryption keys, and HMAC secrets used in the established SA:
   ```bash
sudo ip xfrm state
   ```
 1. Right-click on an ESP packet in Wireshark and select ‘Protocol Preferences’ > ‘ESP SAs…’.
 2. Add the two SAs to the dialog window and paste the necessary values from the terminal.
 3. You should be able to see decrypted ICMP packets in Wireshark.

### 8. List the Entries in the SPD
Use the following command to list the entries in the SPD:
   ```bash
sudo ip xfrm policy
   ```
**Purpose of the Other Encircled Fields:**

```src```: Specifies the source IP address or range for the policy.
```dst```: Specifies the destination IP address or range for the policy.
```dir```: Indicates the direction of the traffic (in for incoming, out for outgoing).
```priority```: Specifies the policy's priority.
```tmpl```: Defines the template for IPsec encapsulation.
```proto```: Specifies the IPsec protocol (e.g., esp for encryption).
```reqid```: Links the SPD entry to a corresponding SA in the SAD.
```mode```: Specifies the IPsec mode (transport or tunnel).

## Host-to-Host Transport Mode VPN with Certificate Authentication
Improve the security of the VPN by changing the strongSwan configuration from PSK authentication to certificate authentication.

### Steps:
 1. Generate server keys and certificates for Server A and Server B using OpenSSL.
 2. Sign the certificates with CA1 to create a trusted chain of authentication.
 3. Place certificates and keys in the correct directories:
      Server certificates: ```/etc/ipsec.d/certs/```
      Private keys: ```/etc/ipsec.d/private/```
      CA certificates: ```/etc/ipsec.d/cacerts/```
### 2. Validate Certificates
 1. Force strongSwan to read the CA certs:
   ```bash
sudo ipsec rereadcacerts
   ```
 2. List the discovered CA certs:
   ```bash
sudo ipsec listcacerts
   ```
 3. Transfer the necessary certificate and key files from Server A to Server B, and place them in the ```/etc/ipsec.d/``` directory.

### 3. Verify the Connection
Check the connection status to confirm it's established:
   ```bash
sudo ipsec status
   ```
### 4. Tunnel Mode VPN with Certificate Authentication between Server A and Server B
 1. Modify ```ipsec.conf``` and ```ipsec.secrets``` for Tunnel Mode.
 2. Test connectivity by pinging the private IP addresses of Server A (192.168.60.100) and Server B (192.168.80.100).

### 5. Tunnel Mode VPN with IP Forwarding for Client A and Client B
 1. Enable IP forwarding on both Server A and Server B:
   ```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p
   ```
 2. Set the default gateway on Client A to Server A (192.168.60.100) and on Client B to Server B (192.168.80.100).
 3. Modify ipsec.conf to include the subnet.
 4. Apply the configuration and verify the connection.

### 6. Routing
Add routes to ensure that the subnets are routed through the VPN tunnel:
   ```bash
sudo ip route add 192.168.80.0/24 dev (interface)
sudo ip route add 192.168.60.0/24 dev (interface)
   ```

### 7. Firewall Rules
Update firewall rules on both Server A and Server B to allow traffic for the subnets through the IPsec tunnel:
   ```bash
sudo iptables -A FORWARD -s 192.168.60.0/24 -d 192.168.80.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.80.0/24 -d 192.168.60.0/24 -j ACCEPT
   ```
### 8. Test the Tunnel
 1. From Client A, ping Client B:
   ```bash
ping 192.168.80.111
   ```
 2. Use tcpdump to monitor traffic containing ESP on both Server A and Server B:
   ```bash
sudo tcpdump -i (interface) esp
   ```

### 9. Site A to Site B VPN with Default DROP Firewall Rules
Change the default iptables policy to DROP on both Server A and Server B.

 1. Copy the ```firewall.sh``` file from the firewall configuration lab and place it on both Server A and Server B, renaming it to iptables.sh.
 2. Update the local subnet, host-only IP address, and VPN interface according to the output of ifconfig.
 3. Modify the iptables rules to allow communication between Client A and Client B over the tunnel.
 4. Restart the strongSwan service.
 5. Now, Client A and Client B can access the Internet through the NAT interface of Server A and Server B, respectively.



#### In this project, I will provide you only the following files:

- **`ipsec.conf`**: The IPsec configuration file for both Server A and Server B. This file contains settings for establishing VPN connections, but it doesn’t hold sensitive information like private keys or passwords.
  
- **`iptables.sh`**: The firewall script used to configure the firewall rules for both Server A and Server B.

The certificates needed for the VPN setup (e.g., server certificates, client certificates, and CA certificates) are not included in this repository for security reasons. 

If you follow the instructions in this repository, you will be able to create and sign the certificates on your own. 

Good luck!
