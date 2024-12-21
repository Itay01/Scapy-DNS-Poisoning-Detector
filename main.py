from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP

# list of suspicious IP addresses
SUSPICIOUS_IPS = ["1.1.1.1", "2.2.2.2", "8.8.8.8"]


def detect_dns_poisoning(pkt):
    if DNS in pkt and pkt[DNS].qr == 1:
        dns_layer = pkt[DNS]

        # Flags for detection test
        multiple_answers_detected = False
        low_ttl_detected = False
        suspicious_ip_detected = False

        # Check 1: Multiple answers for the same query
        if dns_layer.ancount > 1:
            print("[!] Alert: Possible DNS poisoning - multiple answers (ANCOUNT > 1)")
            multiple_answers_detected = True

        for i in range(dns_layer.ancount):
            rr = dns_layer.an[i]

            # Check 2: Suspiciously low TTL (less than 60)
            if rr.ttl < 60:
                print(f"[!] Alert: Possible DNS poisoning - Low TTL ({rr.ttl}) for domain {rr.rrname.decode()}")
                low_ttl_detected = True

            # Check 3: Suspicious IP address if this is an A record (type=1)
            if rr.type == 1:
                ip_addr = rr.rdata
                if ip_addr in SUSPICIOUS_IPS:
                    print(
                        f"[!] Alert: Possible DNS poisoning - Suspicious IP {ip_addr} for domain {rr.rrname.decode()}")
                    suspicious_ip_detected = True

        # Print summary of detections
        print("\n=== Detection Summary ===")
        print(f"Multiple Answers Detected: {multiple_answers_detected}")
        print(f"Low TTL Detected: {low_ttl_detected}")
        print(f"Suspicious IP Detected: {suspicious_ip_detected}")
        print("=========================\n")


def create_malicious_dns_response():
    """
    Creates a fake DNS response packet with:
      - ancount=2 (multiple answers)
      - low TTL (30)
      - suspicious IPs from the list
    """
    packet = (
            IP(dst="127.0.0.1", src="8.8.8.8") /
            UDP(dport=9999, sport=53) /  # Using 9999 for example
            DNS(
                qr=1,  # Response
                id=0xABCD,  # Transaction ID
                qdcount=1,  # Number of questions
                ancount=2,  # Number of answers
                qd=DNSQR(qname="example.com"),  # DNS Question
                an=[
                    DNSRR(rrname="example.com", type="A", ttl=30, rdata="1.1.1.1"),
                    DNSRR(rrname="example.com", type="A", ttl=30, rdata="2.2.2.2")
                ]
            )
    )
    return packet


def test_dns_poisoning():
    malicious_pkt = create_malicious_dns_response()

    print("=== Testing the DNS poisoning detector with artificial packets ===")
    detect_dns_poisoning(malicious_pkt)


if __name__ == "__main__":
    test_dns_poisoning()
