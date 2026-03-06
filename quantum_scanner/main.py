from collections import deque
from core.port_scanner    import scan_all_ports, get_tls_ports, get_vpn_nodes
from core.cert_extractor  import get_certificate
from core.dns_enumerator  import enumerate_subdomains
from rich.console import Console
from rich.table   import Table

console = Console()


def full_scan(target_domain: str):
    """
    Full BFS scan combining all 3 steps.

    BFS Queue starts with target domain.
    DNS enumerator expands it into subdomains.
    Port scanner finds services on each.
    Cert extractor fingerprints TLS on each.
    """

    console.print(f"\n[bold magenta]{'═'*55}[/bold magenta]")
    console.print(f"[bold magenta]  QUANTUM SCANNER — Target: {target_domain}[/bold magenta]")
    console.print(f"[bold magenta]{'═'*55}[/bold magenta]")

    cbom = []              # Final cryptographic inventory
    visited = set()
    queue = deque()

    # ── STEP 3: Seed BFS queue via DNS enumeration ────────────────
    console.print("\n[bold yellow][ STEP 3 ] DNS Subdomain Discovery[/bold yellow]")
    subdomains = enumerate_subdomains(target_domain)
    
    # Add root domain + all discovered subdomains to BFS queue
    queue.append(target_domain)
    for sub in subdomains:
        queue.append(sub.subdomain)

    console.print(
        f"\n[green]BFS Queue loaded: "
        f"{len(queue)} hosts to scan[/green]"
    )

    # ── BFS LOOP ──────────────────────────────────────────────────
    while queue:
        host = queue.popleft()

        if host in visited:
            continue
        visited.add(host)

        console.print(f"\n[cyan]→ Scanning: {host}[/cyan]")

        # ── STEP 2: Port scan this host ───────────────────────────
        port_results = scan_all_ports(host)
        tls_ports    = get_tls_ports(port_results)
        vpn_nodes    = get_vpn_nodes(port_results)

        # ── STEP 1: Cert extract each TLS port ────────────────────
        for port in tls_ports:
            cert_data = get_certificate(host, port.port)

            if not cert_data["reachable"]:
                continue

            cert = cert_data["certificate"]

            # ── SANs → new BFS nodes ───────────────────────────────
            for san in cert["subject_alternative_names"]:
                san = san.lstrip("*.")
                if san not in visited and san.endswith(target_domain):
                    queue.append(san)

            # ── Build CBOM entry ───────────────────────────────────
            cbom.append({
                "host":            host,
                "port":            port.port,
                "service":         port.service_type.value,
                "is_vpn":          port.is_vpn,
                "hndl_multiplier": port.hndl_multiplier,
                "tls_version":     cert_data.get("tls_version"),
                "cipher_suite":    cert_data.get("negotiated_cipher", {}).get("name"),
                "key_algorithm":   cert["public_key_algorithm"],
                "key_size":        cert["key_size_bits"],
                "cert_expiry":     cert["valid_until"],
                "days_left":       cert["days_until_expiry"],
                "is_quantum_vulnerable": cert["is_quantum_vulnerable"],
                "risk_reason":     cert["quantum_risk_reason"],
                "sans_discovered": len(cert["subject_alternative_names"]),
            })

    # ── Final CBOM Table ──────────────────────────────────────────
    console.print(f"\n\n[bold magenta]{'═'*55}[/bold magenta]")
    console.print("[bold magenta]  CRYPTOGRAPHIC BILL OF MATERIALS (CBOM)[/bold magenta]")
    console.print(f"[bold magenta]{'═'*55}[/bold magenta]\n")

    table = Table(show_lines=True)
    table.add_column("Host",        style="cyan",   width=28)
    table.add_column("Port/Svc",    style="white",  width=12)
    table.add_column("TLS Ver",     style="yellow", width=9)
    table.add_column("Key Algo",    style="white",  width=10)
    table.add_column("VPN",         style="red",    width=5)
    table.add_column("Quantum",     style="red",    width=18)

    for entry in cbom:
        quantum_label = (
            "[red]🔴 VULNERABLE[/red]"
            if entry["is_quantum_vulnerable"]
            else "[green]🟢 SAFE[/green]"
        )
        vpn_flag = "[red]⚠️[/red]" if entry["is_vpn"] else "—"

        table.add_row(
            entry["host"][:28],
            f":{entry['port']} {entry['service']}",
            entry.get("tls_version", "?"),
            str(entry.get("key_algorithm", "?"))[:10],
            vpn_flag,
            quantum_label
        )

    console.print(table)
    console.print(
        f"\n[bold]Total assets in CBOM  : {len(cbom)}[/bold]\n"
        f"[red]Quantum Vulnerable    : "
        f"{sum(1 for e in cbom if e['is_quantum_vulnerable'])}[/red]\n"
        f"[green]Quantum Safe          : "
        f"{sum(1 for e in cbom if not e['is_quantum_vulnerable'])}[/green]"
    )

    return cbom

      
