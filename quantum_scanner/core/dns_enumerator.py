import dns.resolver
import dns.exception
import requests
import json
import concurrent.futures
import time
from dataclasses import dataclass
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


# ══════════════════════════════════════════════════════════════════
# WORDLIST — Your Brute Force Dictionary
# ══════════════════════════════════════════════════════════════════

# Common subdomains for public-facing banking/fintech infrastructure
# You can extend this list — more words = more discovery
SUBDOMAIN_WORDLIST = [

    # Web tier
    "www", "web", "portal", "secure", "online",
    "www2", "www3", "m", "mobile", "app",

    # API tier ← Most important for your scanner
    "api", "api2", "api-v1", "api-v2", "apis",
    "rest", "graphql", "gateway", "apigw",
    "services", "service", "microservice",

    # Auth / Identity
    "auth", "login", "sso", "oauth",
    "identity", "id", "account", "accounts",
    "iam", "idp", "saml",

    # VPN / Remote Access ← HNDL targets
    "vpn", "vpn2", "remote", "access",
    "ssl-vpn", "sslvpn", "ra", "citrix",
    "anyconnect", "globalprotect",

    # Banking specific
    "netbanking", "ibanking", "ebanking",
    "payments", "pay", "transaction",
    "cards", "card", "credit", "debit",
    "loans", "mortgage", "invest",

    # Infrastructure
    "mail", "email", "smtp", "mx",
    "cdn", "static", "assets", "media",
    "dev", "staging", "uat", "test",
    "admin", "panel", "dashboard",
    "monitor", "status", "health",

    # Security
    "cert", "pki", "ca", "ocsp",
    "crl", "waf", "proxy", "firewall",
]


# ══════════════════════════════════════════════════════════════════
# DATA STRUCTURE
# ══════════════════════════════════════════════════════════════════

@dataclass
class SubdomainResult:
    subdomain: str          # full hostname e.g api.bank.com
    base_domain: str        # e.g bank.com
    discovery_method: str   # brute_force / ct_logs / dns_records
    ip_addresses: list      # resolved IPs
    is_wildcard: bool       # wildcard cert covers this?
    cname: Optional[str]    # points to another domain?
    extra_domains: list     # other domains from same cert/record

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "base_domain": self.base_domain,
            "discovery_method": self.discovery_method,
            "ip_addresses": self.ip_addresses,
            "is_wildcard": self.is_wildcard,
            "cname": self.cname,
            "extra_domains": self.extra_domains,
            "is_internet_exposed": len(self.ip_addresses) > 0
        }


# ══════════════════════════════════════════════════════════════════
# TECHNIQUE 1 — DNS BRUTE FORCE
# ══════════════════════════════════════════════════════════════════

def resolve_subdomain(subdomain: str) -> Optional[SubdomainResult]:
    """
    Try to resolve a single subdomain.
    Returns result if it exists, None if it doesn't.
    """
    base = ".".join(subdomain.split(".")[-2:])  # extract base domain

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        # ── Try A record first (IPv4) ──────────────────────────────
        try:
            a_records = resolver.resolve(subdomain, "A")
            ips = [str(r) for r in a_records]

            # ── Also check for CNAME (points elsewhere) ───────────
            cname = None
            try:
                cname_records = resolver.resolve(subdomain, "CNAME")
                cname = str(cname_records[0].target)
            except:
                pass

            return SubdomainResult(
                subdomain=subdomain,
                base_domain=base,
                discovery_method="brute_force",
                ip_addresses=ips,
                is_wildcard=False,
                cname=cname,
                extra_domains=[]
            )
        except dns.resolver.NXDOMAIN:
            return None  # Subdomain does not exist
        except dns.resolver.NoAnswer:
            return None

    except Exception:
        return None


def brute_force_subdomains(
    domain: str,
    wordlist: list = SUBDOMAIN_WORDLIST,
    max_workers: int = 50
) -> list[SubdomainResult]:
    """
    Tests every word in wordlist as a subdomain — concurrently.
    50 workers = 50 DNS queries at once → fast.
    """
    candidates = [f"{word}.{domain}" for word in wordlist]
    discovered = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[yellow]Brute forcing DNS... {task.completed}/{task.total}"),
        console=console
    ) as progress:

        task = progress.add_task("dns", total=len(candidates))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(resolve_subdomain, candidate): candidate
                for candidate in candidates
            }

            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    discovered.append(result)

    return discovered


# ══════════════════════════════════════════════════════════════════
# TECHNIQUE 2 — CERTIFICATE TRANSPARENCY LOGS
# ══════════════════════════════════════════════════════════════════

def query_ct_logs(domain: str) -> list[SubdomainResult]:
    """
    Certificate Transparency: By law, every TLS cert issued
    must be logged publicly. crt.sh exposes this as an API.

    This reveals subdomains that DNS brute force might miss
    — including ones the target tried to keep quiet.
    """
    discovered = []
    seen = set()

    console.print("[yellow]  Querying Certificate Transparency logs (crt.sh)...[/yellow]")

    try:
        # ── Hit the crt.sh JSON API ────────────────────────────────
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            console.print("[red]  CT logs unavailable[/red]")
            return []

        entries = response.json()
        console.print(f"  [green]CT logs returned {len(entries)} certificate entries[/green]")

        for entry in entries:
            # Each cert entry has name_value field with domains
            # Can contain multiple domains separated by newlines
            raw_names = entry.get("name_value", "")
            names = raw_names.replace("\r", "").split("\n")

            for name in names:
                name = name.strip().lower()

                # Skip wildcards and duplicates
                if name.startswith("*"):
                    # But still note the base domain exists
                    base_from_wildcard = name.lstrip("*.")
                    name = base_from_wildcard

                if name in seen:
                    continue
                if not name.endswith(domain):
                    continue

                seen.add(name)

                # ── Resolve to confirm it's live ───────────────────
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2
                    a_records = resolver.resolve(name, "A")
                    ips = [str(r) for r in a_records]
                except:
                    ips = []  # Cert exists but DNS not active

                result = SubdomainResult(
                    subdomain=name,
                    base_domain=domain,
                    discovery_method="ct_logs",
                    ip_addresses=ips,
                    is_wildcard="*" in raw_names,
                    cname=None,
                    extra_domains=[]
                )
                discovered.append(result)

        # Rate limit — be polite to crt.sh
        time.sleep(1)

    except requests.RequestException as e:
        console.print(f"[red]  CT log query failed: {e}[/red]")
    except json.JSONDecodeError:
        console.print("[red]  CT log response was not valid JSON[/red]")

    return discovered


# ══════════════════════════════════════════════════════════════════
# TECHNIQUE 3 — DNS RECORD MINING
# ══════════════════════════════════════════════════════════════════

def mine_dns_records(domain: str) -> list[SubdomainResult]:
    """
    Query special DNS record types that reveal infrastructure.

    MX  → mail servers (e.g mail.bank.com)
    NS  → nameservers (reveals DNS provider)
    TXT → SPF, DKIM, verification tokens — often contain subdomains
    SOA → Start of Authority — reveals primary nameserver
    """
    discovered = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3

    record_types = ["MX", "NS", "TXT", "SOA"]
    console.print("[yellow]  Mining DNS records (MX, NS, TXT, SOA)...[/yellow]")

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)

            for rdata in answers:
                rdata_str = str(rdata).lower()

                # ── Extract hostnames from record values ───────────
                # MX: "10 mail.bank.com." → extract mail.bank.com
                # NS: "ns1.bank.com."     → extract ns1.bank.com
                extracted = []

                if rtype == "MX":
                    # MX format: "priority hostname"
                    parts = rdata_str.split()
                    if len(parts) >= 2:
                        host = parts[1].rstrip(".")
                        if domain in host:
                            extracted.append(host)

                elif rtype == "NS":
                    host = rdata_str.rstrip(".")
                    if domain in host:
                        extracted.append(host)

                elif rtype == "TXT":
                    # TXT records often contain:
                    # v=spf1 include:mail.bank.com ~all
                    # Look for include: and a: directives
                    import re
                    hosts = re.findall(
                        r'(?:include:|a:)([\w\.\-]+)',
                        rdata_str
                    )
                    for h in hosts:
                        if domain in h:
                            extracted.append(h)

                for host in extracted:
                    try:
                        a_records = resolver.resolve(host, "A")
                        ips = [str(r) for r in a_records]
                    except:
                        ips = []

                    result = SubdomainResult(
                        subdomain=host,
                        base_domain=domain,
                        discovery_method=f"dns_{rtype.lower()}_record",
                        ip_addresses=ips,
                        is_wildcard=False,
                        cname=None,
                        extra_domains=[]
                    )
                    discovered.append(result)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout):
            pass
        except Exception as e:
            console.print(f"[dim]  {rtype} record query failed: {e}[/dim]")

    return discovered


# ══════════════════════════════════════════════════════════════════
# MASTER ENUMERATOR — Combines All 3 Techniques
# ══════════════════════════════════════════════════════════════════

def enumerate_subdomains(domain: str) -> list[SubdomainResult]:
    """
    Runs all 3 discovery techniques and deduplicates results.
    This is what feeds your BFS queue in main.py.
    """
    console.print(f"\n[bold cyan]DNS Enumeration: {domain}[/bold cyan]")
    all_results = []
    seen_hosts = set()

    # ── Run all 3 techniques ──────────────────────────────────────
    console.print("\n[bold]Technique 1: DNS Brute Force[/bold]")
    brute_results = brute_force_subdomains(domain)
    console.print(f"  Found: [green]{len(brute_results)}[/green] subdomains")

    console.print("\n[bold]Technique 2: Certificate Transparency Logs[/bold]")
    ct_results = query_ct_logs(domain)
    console.print(f"  Found: [green]{len(ct_results)}[/green] subdomains")

    console.print("\n[bold]Technique 3: DNS Record Mining[/bold]")
    dns_results = mine_dns_records(domain)
    console.print(f"  Found: [green]{len(dns_results)}[/green] subdomains")

    # ── Deduplicate across all 3 techniques ───────────────────────
    for result in brute_results + ct_results + dns_results:
        if result.subdomain not in seen_hosts:
            seen_hosts.add(result.subdomain)
            all_results.append(result)

    # ── Only return internet-exposed ones ─────────────────────────
    # (Has a real IP = internet facing = in scope for your scanner)
    live_results = [r for r in all_results if r.ip_addresses]

    console.print(f"\n[bold]Total unique subdomains discovered : {len(all_results)}[/bold]")
    console.print(f"[bold green]Internet-exposed (live)            : {len(live_results)}[/bold green]")

    return live_results
