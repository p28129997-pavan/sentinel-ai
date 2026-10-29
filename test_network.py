import sys
import argparse
from detection.rules import NetworkAnalyzer

def test_network_cli():
    print("\n" + "="*70)
    print("   SENTINEL AI -- Live Network Flow & C2 Threat Analyzer")
    print("="*70)

    parser = argparse.ArgumentParser(description="Test arbitrary network connections in SENTINEL AI")
    parser.add_argument("--dst-ip", default="", help="Destination IP address (e.g. 198.51.100.45)")
    parser.add_argument("--dst-port", type=int, default=0, help="Destination Port (e.g. 4444, 443, 8888)")
    parser.add_argument("--bytes", type=int, default=0, help="Outbound bytes sent (e.g. 142500000 for 142MB)")
    parser.add_argument("--domain", default="", help="Destination domain name")
    parser.add_argument("--beacon", action="store_true", help="Flag as repeated heartbeat beaconing")

    args = parser.parse_args()

    dst_ip = args.dst_ip
    dst_port = args.dst_port
    bytes_sent = args.bytes
    domain = args.domain
    beacon = args.beacon

    if not dst_ip and dst_port == 0:
        print("\n[?] Interactive Network Flow Input (Press Enter for sample C2 flow):")
        inp_ip = input("    Destination IP [default: 198.51.100.45]: ").strip()
        dst_ip = inp_ip if inp_ip else "198.51.100.45"

        inp_port = input("    Destination Port [default: 4444]: ").strip()
        dst_port = int(inp_port) if inp_port else 4444

        inp_bytes = input("    Bytes Sent [default: 142500000 (142.5 MB)]: ").strip()
        bytes_sent = int(inp_bytes) if inp_bytes else 142500000

        inp_domain = input("    Destination Domain [default: invoice-secure-portal.xyz]: ").strip()
        domain = inp_domain if inp_domain else "invoice-secure-portal.xyz"

    res = NetworkAnalyzer.analyze_flow(
        dst_ip=dst_ip,
        dst_port=dst_port,
        bytes_sent=bytes_sent,
        dst_domain=domain,
        is_beacon=beacon
    )

    verdict_color = "\033[91m" if "CRITICAL" in res["verdict"] else "\033[93m" if "SUSPICIOUS" in res["verdict"] else "\033[92m"
    reset_color = "\033[0m"

    print("\n" + "-" * 70)
    print(f"[*] THREAT VERDICT:   {verdict_color}{res['verdict']}{reset_color}")
    print(f"[*] RISK SCORE:       {res['risk_score']}/100")
    print(f"[*] TARGET FLOW:      10.0.1.15 -> {res['dst_ip']}:{res['dst_port']} (TCP)")
    print(f"[*] DATA VOLUME:      {res['mb_sent']} MB ({res['bytes_sent']:,} bytes)")
    if domain:
        print(f"[*] EGRESS DOMAIN:    {domain}")
    print("-" * 70)
    print("[*] DETECTION FINDINGS:")
    for f in res["findings"]:
        print(f"    --> {f}")

    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    test_network_cli()
