#!/usr/bin/env python3
"""
=============================================================
  Phishing Awareness Analyzer — DecodeLabs Project 3 (2026)
  Platform : Kali Linux
  Purpose  : Triage suspicious emails and URLs using
             header inspection, domain checks, and red-flag
             pattern matching. Zero external API keys needed.
=============================================================
"""

import re
import sys
import json
import socket
import argparse
import subprocess
import urllib.parse
from datetime import datetime

# ─────────────────────────────────────────────
#   ANSI COLOUR PALETTE
# ─────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    AMBER  = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

def red(t):   return f"{C.RED}{t}{C.RESET}"
def amber(t): return f"{C.AMBER}{t}{C.RESET}"
def green(t): return f"{C.GREEN}{t}{C.RESET}"
def cyan(t):  return f"{C.CYAN}{t}{C.RESET}"
def bold(t):  return f"{C.BOLD}{t}{C.RESET}"
def dim(t):   return f"{C.DIM}{t}{C.RESET}"

# ─────────────────────────────────────────────
#   BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
 ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██████╗
 ██╔══██╗██║  ██║██║██╔════╝██║  ██║╚════██╗
 ██████╔╝███████║██║███████╗███████║  ████╔╝
 ██╔═══╝ ██╔══██║██║╚════██║██╔══██║ ██╔══╝
 ██║     ██║  ██║██║███████║██║  ██║ ███████╗
 ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝{C.RESET}

 {C.DIM}Phishing Awareness Analyzer — DecodeLabs 2026{C.RESET}
 {C.DIM}Industrial Training Kit :: Project 3{C.RESET}
{'─' * 52}
"""

# ─────────────────────────────────────────────
#   KNOWN SUSPICIOUS PATTERNS
# ─────────────────────────────────────────────
URGENCY_PATTERNS = [
    r"urgent", r"immediate", r"expires?\s+in\s+\d+\s+hour",
    r"act\s+now", r"within\s+24\s+hours?", r"account.*lock",
    r"suspend", r"terminate", r"immediately", r"last.?chance",
    r"verify\s+now", r"confirm\s+now",
]

CREDENTIAL_PATTERNS = [
    r"password", r"passphrase", r"credentials?", r"login\s+detail",
    r"otp", r"one.?time.?password", r"mfa\s+code", r"pin\s+number",
    r"social\s+security", r"credit\s+card", r"bank\s+account",
    r"billing\s+information", r"payment\s+detail",
]

AUTHORITY_PATTERNS = [
    r"ceo", r"chief\s+executive", r"board\s+of\s+directors?",
    r"it\s+(security|support|team)", r"helpdesk", r"human\s+resources",
    r"legal\s+department", r"law\s+enforcement", r"irs", r"government",
    r"microsoft\s+support", r"apple\s+support",
]

BYPASS_PATTERNS = [
    r"do\s+not\s+discuss", r"keep\s+(this|it)\s+(confidential|secret)",
    r"strictly\s+confidential", r"bypass\s+standard", r"skip\s+the\s+process",
    r"don.?t\s+tell\s+anyone", r"between\s+us",
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".vbs", ".js", ".hta", ".bat", ".cmd",
    ".ps1", ".iso", ".lnk", ".jar", ".msi", ".com",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "is.gd", "buff.ly", "rebrand.ly",
]

# ─────────────────────────────────────────────
#   CORE ANALYSIS ENGINE
# ─────────────────────────────────────────────

class PhishingAnalyzer:
    """
    Accepts raw email text or a URL string and produces a
    structured threat assessment with scored red flags.
    """

    def __init__(self, content: str, mode: str = "email"):
        self.content = content.lower()
        self.raw = content
        self.mode = mode          # "email" | "url"
        self.findings = []        # list of (severity, category, detail)
        self.score = 0            # 0–100 threat score
        self.verdict = "SAFE"

    # ── helpers ──────────────────────────────
    def _add(self, severity: str, category: str, detail: str, weight: int = 10):
        self.findings.append((severity, category, detail))
        self.score = min(100, self.score + weight)

    def _search(self, patterns, text=None):
        text = text or self.content
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                return m.group(0)
        return None

    # ── email header analysis ─────────────────
    def check_headers(self):
        lines = self.raw.splitlines()
        from_line = next((l for l in lines if l.lower().startswith("from:")), "")
        reply_line = next((l for l in lines if l.lower().startswith("reply-to:")), "")
        return_line = next((l for l in lines if l.lower().startswith("return-path:")), "")
        subject_line = next((l for l in lines if l.lower().startswith("subject:")), "")

        # Extract raw email address from From:
        addr_match = re.search(r"<([^>]+)>", from_line)
        raw_addr = addr_match.group(1) if addr_match else from_line.replace("From:", "").strip()
        domain_match = re.search(r"@([\w.\-]+)", raw_addr)
        sender_domain = domain_match.group(1).lower() if domain_match else ""

        if sender_domain:
            print(f"  {cyan('SENDER DOMAIN :')} {sender_domain}")
            # Check for free mail providers impersonating corporate
            free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"]
            if any(p in sender_domain for p in free_providers):
                self._add("HIGH", "SENDER", f"Corporate sender using free email provider: {sender_domain}", 20)
            # Check for lookalike keywords in domain
            lookalike_kw = ["secure", "login", "update", "verify", "alert", "support", "portal", "admin"]
            for kw in lookalike_kw:
                if kw in sender_domain and len(sender_domain) > len(kw) + 4:
                    self._add("HIGH", "SENDER", f"Suspicious keyword '{kw}' found in sender domain: {sender_domain}", 15)

        # Reply-To mismatch
        if reply_line:
            reply_addr = re.search(r"@([\w.\-]+)", reply_line)
            if reply_addr and sender_domain and reply_addr.group(1).lower() != sender_domain:
                self._add("HIGH", "HEADER", f"Reply-To domain differs from From domain (possible exfiltration address)", 20)

        # Subject urgency
        if subject_line:
            subj = subject_line.replace("Subject:", "").strip()
            print(f"  {cyan('SUBJECT        :')} {subj[:80]}")
            if re.search(r"urgent|immediate|action\s+required|expires|warning|alert|verify", subj, re.I):
                self._add("MEDIUM", "SUBJECT", f"Urgency language in subject line: '{subj[:60]}'", 10)
            if subj.upper() == subj and len(subj) > 10:
                self._add("LOW", "SUBJECT", "Subject is entirely uppercase — psychological pressure tactic", 5)

        # FW: fake forward
        if re.search(r"^subject:\s*(fw:|fwd:)", from_line + subject_line, re.I):
            self._add("MEDIUM", "HEADER", "FW:/FWD: prefix — possible fake forwarding chain", 8)

    # ── body content analysis ─────────────────
    def check_body(self):
        match = self._search(URGENCY_PATTERNS)
        if match:
            self._add("HIGH", "URGENCY", f"Urgency trigger detected: '{match}'", 15)

        match = self._search(CREDENTIAL_PATTERNS)
        if match:
            self._add("HIGH", "CREDENTIALS", f"Credential request language: '{match}'", 20)

        match = self._search(AUTHORITY_PATTERNS)
        if match:
            self._add("MEDIUM", "AUTHORITY", f"Authority impersonation language: '{match}'", 10)

        match = self._search(BYPASS_PATTERNS)
        if match:
            self._add("HIGH", "BYPASS", f"Isolation/bypass instruction: '{match}'", 20)

        # Dangerous attachments mentioned
        for ext in DANGEROUS_EXTENSIONS:
            if ext in self.content:
                self._add("HIGH", "ATTACHMENT", f"Reference to dangerous file extension: {ext}", 15)
                break

    # ── url analysis ──────────────────────────
    def check_urls_in_text(self):
        urls = re.findall(r"https?://[^\s\"'<>]+", self.raw, re.IGNORECASE)
        if not urls:
            return
        print(f"\n  {cyan('URLS FOUND     :')} {len(urls)}")
        for url in urls[:10]:     # cap at 10 to avoid flooding
            self._analyze_single_url(url, inline=True)

    def _analyze_single_url(self, url: str, inline: bool = False):
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return

        netloc = parsed.netloc.lower()
        print(f"\n  {dim('URL :')} {url[:90]}")

        # URL shortener
        for svc in URL_SHORTENERS:
            if svc in netloc:
                self._add("HIGH", "URL", f"URL shortener hides true destination: {svc}", 20)
                print(f"    {red('▲ URL SHORTENER — destination hidden')}")

        # Subdomain depth trick
        parts = netloc.split(".")
        if len(parts) > 3:
            root = ".".join(parts[-2:])
            fake_sub = ".".join(parts[:-2])
            self._add("HIGH", "URL", f"Deep subdomain — real root is '{root}', subdomain may spoof '{fake_sub}'", 15)
            print(f"    {red(f'▲ SUBDOMAIN TRAP — real root: {root}')}")

        # Combosquatting keywords in domain
        combo_kw = ["secure", "login", "verify", "update", "alert", "support", "account", "portal"]
        for kw in combo_kw:
            if kw in netloc:
                self._add("MEDIUM", "URL", f"Security-related keyword in domain: '{kw}' in {netloc}", 10)
                print(f"    {amber(f'▲ COMBOSQUATTING keyword: {kw}')}")
                break

        # IP address instead of domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", netloc):
            self._add("HIGH", "URL", f"IP address used instead of domain name: {netloc}", 20)
            print(f"    {red('▲ RAW IP ADDRESS — no legitimate use in email links')}")

        # HTTP (not HTTPS) for login pages
        if parsed.scheme == "http" and any(k in url.lower() for k in ["login", "signin", "account", "verify"]):
            self._add("MEDIUM", "URL", "Unencrypted HTTP used for a login/verify page", 10)
            print(f"    {amber('▲ HTTP (unencrypted) login page')}")

        if not inline:
            print()

    # ── standalone URL mode ───────────────────
    def check_url_mode(self):
        self._analyze_single_url(self.raw.strip())

        # Try DNS resolution
        try:
            parsed = urllib.parse.urlparse(self.raw.strip())
            host = parsed.netloc.split(":")[0]
            ip = socket.gethostbyname(host)
            print(f"  {cyan('DNS RESOLVED   :')} {host} → {ip}")
            # Suspicious IP ranges (example: known bad ASNs — simplified check)
            octets = list(map(int, ip.split(".")))
            if octets[0] in [185, 194, 95, 45]:
                self._add("MEDIUM", "DNS", f"IP {ip} is in a frequently abused hosting range", 8)
        except socket.gaierror:
            self._add("HIGH", "DNS", "Domain does not resolve — likely newly registered or taken down", 15)
            print(f"  {red('DNS RESOLUTION : FAILED — domain does not exist or is offline')}")
        except Exception:
            pass

    # ── assemble final verdict ────────────────
    def compute_verdict(self):
        if self.score >= 60:
            self.verdict = "MALICIOUS"
        elif self.score >= 25:
            self.verdict = "SUSPICIOUS"
        else:
            self.verdict = "SAFE"

    # ── main entry point ──────────────────────
    def run(self):
        print(f"\n{'─'*52}")
        print(bold("  ANALYSIS STARTED"))
        print(f"  {cyan('MODE           :')} {self.mode.upper()}")
        print(f"  {cyan('TIMESTAMP      :')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'─'*52}")

        if self.mode == "email":
            self.check_headers()
            self.check_body()
            self.check_urls_in_text()
        elif self.mode == "url":
            self.check_url_mode()

        self.compute_verdict()
        self._print_report()

    # ── report printer ────────────────────────
    def _print_report(self):
        print(f"\n{'═'*52}")
        print(bold("  RED FLAGS DETECTED"))
        print(f"{'═'*52}")

        if not self.findings:
            print(f"  {green('No red flags detected.')}")
        else:
            for sev, cat, detail in self.findings:
                if sev == "HIGH":
                    icon = red("  ▲ HIGH  ")
                elif sev == "MEDIUM":
                    icon = amber("  ▲ MED   ")
                else:
                    icon = dim("  ▲ LOW   ")
                print(f"{icon} {cyan(f'[{cat}]')} {detail}")

        print(f"\n{'═'*52}")
        # Threat score bar
        bar_fill = int(self.score / 5)
        bar = "█" * bar_fill + "░" * (20 - bar_fill)
        score_color = red if self.score >= 60 else amber if self.score >= 25 else green
        print(f"  THREAT SCORE : {score_color(str(self.score) + '/100')}  [{score_color(bar)}]")

        if self.verdict == "MALICIOUS":
            v_str = f"{C.RED}{C.BOLD}  VERDICT      : ▲ MALICIOUS — BLOCK DOMAIN & ESCALATE{C.RESET}"
        elif self.verdict == "SUSPICIOUS":
            v_str = f"{C.AMBER}{C.BOLD}  VERDICT      : ⚠ SUSPICIOUS — WARN USER & VERIFY OUT-OF-BAND{C.RESET}"
        else:
            v_str = f"{C.GREEN}{C.BOLD}  VERDICT      : ✓ SAFE — CLOSE (continue monitoring){C.RESET}"

        print(v_str)
        print(f"{'═'*52}\n")

        print(dim("  NEXT STEPS:"))
        if self.verdict == "MALICIOUS":
            steps = [
                "Do NOT click any link or download any attachment.",
                "Report via internal security plugin (do not delete).",
                "Submit sender domain to: https://urlscan.io",
                "Escalate to security team with full email headers.",
                "Run: whois <domain> and dig <domain> for forensics.",
            ]
        elif self.verdict == "SUSPICIOUS":
            steps = [
                "Do not act on the request until verified.",
                "Call the sender on a known number (not one in the email).",
                "Hover — do not click — all links to inspect full URLs.",
                "If in doubt, report to security team.",
            ]
        else:
            steps = [
                "No immediate action required.",
                "Keep applying the Pause → Verify → Report rule.",
            ]
        for step in steps:
            print(f"  {dim('→')} {step}")
        print()


# ─────────────────────────────────────────────
#   CLI ENTRY POINT
# ─────────────────────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Phishing Awareness Analyzer — DecodeLabs Project 3",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--file", "-f",
        help="Path to a .eml or .txt file containing the suspicious email",
    )
    parser.add_argument(
        "--url", "-u",
        help="A suspicious URL to analyze directly",
    )
    parser.add_argument(
        "--text", "-t",
        help="Paste email body text directly as a string",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a built-in demo with a simulated phishing email",
    )

    args = parser.parse_args()

    # ── DEMO MODE ──────────────────────────────
    if args.demo:
        demo_email = """From: IT-Security <support@logins-updates.com>
To: employee@company.com
Reply-To: attacker@protonmail.com
Subject: URGENT: Your Account Password Expires in 24 Hours

Dear Employee,

Our security system detected that your corporate account password will expire
in 24 hours. Failure to update your credentials immediately will result in
permanent account suspension.

STRICTLY CONFIDENTIAL: Do not discuss this with anyone.
Bypass the standard IT procedure and click the link below now:

https://yourcompany.com.logins-portal-secure.com/reset?token=a8f3k91zx&session=emp001

Please enter your username, password, and OTP code to continue.

— IT Security Team
"""
        print(f"  {amber('DEMO MODE — Simulated Phishing Email Loaded')}\n")
        analyzer = PhishingAnalyzer(demo_email, mode="email")
        analyzer.run()
        return

    # ── FILE MODE ──────────────────────────────
    if args.file:
        try:
            with open(args.file, "r", errors="replace") as fh:
                content = fh.read()
            analyzer = PhishingAnalyzer(content, mode="email")
            analyzer.run()
        except FileNotFoundError:
            print(red(f"  Error: File not found: {args.file}"))
            sys.exit(1)
        return

    # ── URL MODE ───────────────────────────────
    if args.url:
        analyzer = PhishingAnalyzer(args.url, mode="url")
        analyzer.run()
        return

    # ── DIRECT TEXT MODE ───────────────────────
    if args.text:
        analyzer = PhishingAnalyzer(args.text, mode="email")
        analyzer.run()
        return

    # ── INTERACTIVE MODE ───────────────────────
    print(f"  {cyan('INTERACTIVE MODE')}")
    print(f"  {dim('Choose input method:')}")
    print(f"  {dim('[1]')} Paste email text  (end with a line containing only 'END')")
    print(f"  {dim('[2]')} Enter a URL")
    print(f"  {dim('[3]')} Run built-in demo")
    print()
    choice = input(f"  {cyan('>')} ").strip()

    if choice == "1":
        print(f"  {dim('Paste email content below. Type END on a new line when finished.')}")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        content = "\n".join(lines)
        analyzer = PhishingAnalyzer(content, mode="email")
        analyzer.run()

    elif choice == "2":
        url = input(f"  {cyan('Enter URL >')} ").strip()
        analyzer = PhishingAnalyzer(url, mode="url")
        analyzer.run()

    elif choice == "3":
        import subprocess
        subprocess.run([sys.executable, __file__, "--demo"])

    else:
        print(red("  Invalid choice. Run with --help for usage."))
        sys.exit(1)


if __name__ == "__main__":
    main()
