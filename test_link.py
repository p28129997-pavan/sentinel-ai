import sys
import json
from detection.rules import URLAnalyzer

def test_url_interactive():
    print("\n" + "="*70)
    print("   SENTINEL AI -- Live URL & Phishing Link Threat Analyzer")
    print("="*70)

    if len(sys.argv) > 1:
        test_url = sys.argv[1]
    else:
        test_url = input("\n[?] Enter any random link/URL to inspect (or press Enter for test sample): ").strip()
        if not test_url:
            test_url = "http://paypa1-security-login.xyz/verify/account?token=9283"

    print(f"\n[*] Analyzing URL: {test_url}...")
    res = URLAnalyzer.analyze_url(test_url)

    verdict_color = "\033[91m" if "MALICIOUS" in res["verdict"] else "\033[93m" if "SUSPICIOUS" in res["verdict"] else "\033[92m"
    reset_color = "\033[0m"

    print("-" * 70)
    print(f"[*] VERDICT:          {verdict_color}{res['verdict']}{reset_color}")
    print(f"[*] RISK SCORE:       {res['risk_score']}/100")
    print(f"[*] NORMALIZED HOST:  {res['hostname']}")
    print("-" * 70)
    print("[*] DETECTION FINDINGS:")
    if res["findings"]:
        for f in res["findings"]:
            print(f"    --> {f}")
    else:
        print("    [+] No threat indicators detected. Standard benign domain structure.")

    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    test_url_interactive()
