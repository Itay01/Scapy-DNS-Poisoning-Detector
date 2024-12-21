# Scapy DNS Poisoning Detector

This repository provides a simple script that demonstrates how to detect potential DNS poisoning attacks using **Scapy**. The script inspects DNS response packets for multiple indications of suspicious behavior:

1. **Multiple Answers** for the same query (`ANCOUNT > 1`).  
2. **Low TTL** (less than 60 seconds).  
3. **Suspicious IP Addresses** (compared to a predefined list).

## How It Works

The script includes three main functions:

1. **`detect_dns_poisoning(pkt)`**  
   Inspects a DNS response packet (where `pkt[DNS].qr == 1`) for signs of poisoning, such as:
   - More than one DNS answer  
   - TTL less than 60 seconds  
   - Matches against known suspicious IPs (`SUSPICIOUS_IPS`)

2. **`create_malicious_dns_response()`**  
   Generates a fake DNS response packet for testing. This packet includes two answers (multiple answers), a low TTL (30 seconds), and suspicious IPs (`1.1.1.1` and `2.2.2.2`).

3. **`test_dns_poisoning()`**  
   Creates the malicious DNS packet and then calls `detect_dns_poisoning(pkt)` on it, allowing you to see detection warnings in action.

## Requirements

- **Python 3.x**
- **Scapy** (install via `pip install scapy`)

## Installation

1. Clone this repository or copy the script into a file named, for example, `dns_poisoning_detector.py`.
2. Make sure you have [Scapy installed](https://scapy.readthedocs.io/en/latest/installation.html):
   ```bash
   pip install scapy
   ```

## Usage

1. Run the script directly:
   ```bash
   python dns_poisoning_detector.py
   ```
2. The script will create a malicious DNS response and pass it to the detector function.  
3. Check your console for alerts about:
   - **Multiple DNS answers**  
   - **Low TTL**  
   - **Suspicious IP addresses**  

You should see output like:
```
=== Testing the DNS poisoning detector with artificial packets ===
[!] Alert: Possible DNS poisoning - multiple answers (ANCOUNT > 1)
[!] Alert: Possible DNS poisoning - Low TTL (30) for domain example.com.
[!] Alert: Possible DNS poisoning - Suspicious IP 1.1.1.1 for domain example.com.
[!] Alert: Possible DNS poisoning - Low TTL (30) for domain example.com.
[!] Alert: Possible DNS poisoning - Suspicious IP 2.2.2.2 for domain example.com.

=== Detection Summary ===
Multiple Answers Detected: True
Low TTL Detected: True
Suspicious IP Detected: True
=========================
```

## Customizing

- **Suspicious IPs**  
  Edit the list `SUSPICIOUS_IPS` at the top of the script to include IP addresses you want to flag as suspicious.

- **TTL Threshold**  
  By default, the script flags any TTL less than 60. You can adjust this value to your preferred threshold.

- **Adding Checks**  
  You can add further checks for other record types (e.g., `MX`, `CNAME`) or compare the `Transaction ID` with actual requests.  

---
