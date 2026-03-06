from core.port_scanner import scan_all_ports, get_tls_ports, get_vpn_nodes
from core.cert_extractor import get_certificate
from rich.console import Console

console = Console()

def scan_host(hostname: str):
    console.print(f"\n[bold cyan]═══ Scanning: {hostname} ═══[/bold cyan]")

    # ── Step 2: Find all open ports ───────────────────────────────
    console.print("[yellow]Step 2: Port scanning...[/yellow]")
    port_results = scan_all_ports(hostname)
    tls_ports    = get_tls_ports(port_results)
    vpn_nodes    = get_vpn_nodes(port_results)

    console.print(f"  Found {len(tls_ports)} TLS ports, {len(vpn_nodes)} VPN endpoints")

    # ── Step 1: Extract cert from each TLS port ───────────────────
    console.print("[yellow]Step 1: Extracting certificates...[/yellow]")
    for port_result in tls_ports:
        cert_data = get_certificate(hostname, port_result.port)

        if cert_data["reachable"]:
            cert = cert_data["certificate"]
            status = "🔴 VULNERABLE" if cert["is_quantum_vulnerable"] else "🟢 SAFE"
            console.print(
                f"  :{port_result.port} [{port_result.service_type.value}] "
                f"→ {status} | {cert['public_key_algorithm']} "
                f"| TLS: {cert_data['tls_version']}"
            )

            # SANs = new nodes for BFS (Step 3 will use these)
            if cert["subject_alternative_names"]:
                console.print(
                    f"    SANs discovered: {len(cert['subject_alternative_names'])} "
                    f"new nodes → {cert['subject_alternative_names'][:3]}..."
                )

    # ── VPN Warning ───────────────────────────────────────────────
    if vpn_nodes:
        console.print("\n[bold red]⚠️  HNDL HIGH PRIORITY — VPN Endpoints:[/bold red]")
        for vpn in vpn_nodes:
            console.print(
                f"  → Port {vpn.port} [{vpn.service_type.value}] "
                f"HNDL Multiplier: {vpn.hndl_multiplier}x"
            )

      
