"""
Step 5: Report Generator
=========================
Takes scored CBOM data → outputs a full HTML report with:
  - Executive summary dashboard
  - Per-asset breakdown with risk scores
  - PQC certificates rendered visually
  - Remediation playbook
  - CBOM export as JSON
"""

import json
import os
from datetime import datetime
from core.risk_scorer import QuantumLabel


def generate_report(scored_results: list, target_domain: str, output_dir: str = "reports") -> str:
    """
    Master function — builds complete HTML report from scored CBOM.
    Returns path to generated file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(output_dir, f"quantum_report_{target_domain}_{timestamp}.html")
    cbom_path   = os.path.join(output_dir, f"cbom_{target_domain}_{timestamp}.json")

    # Build stats for summary
    total       = len(scored_results)
    vulnerable  = sum(1 for s in scored_results if s.label == QuantumLabel.QUANTUM_VULNERABLE)
    transitioning = sum(1 for s in scored_results if s.label == QuantumLabel.QUANTUM_TRANSITIONING)
    safe        = sum(1 for s in scored_results if s.label == QuantumLabel.FULLY_QUANTUM_SAFE)
    pqc_certs   = sum(1 for s in scored_results if s.certificate_awarded)
    vpn_count   = sum(1 for s in scored_results if s.is_vpn)
    avg_score   = round(sum(s.total_score for s in scored_results) / total, 1) if total else 0

    # Export raw CBOM JSON
    cbom_export = [s.to_dict() for s in scored_results]
    with open(cbom_path, "w") as f:
        json.dump({
            "target": target_domain,
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_assets": total, "vulnerable": vulnerable,
                "transitioning": transitioning, "quantum_safe": safe,
                "pqc_certificates": pqc_certs, "average_risk_score": avg_score
            },
            "assets": cbom_export
        }, f, indent=2)

    # Build asset cards HTML
    asset_cards = ""
    for s in scored_results:
        label_class = {
            QuantumLabel.QUANTUM_VULNERABLE:    "vulnerable",
            QuantumLabel.QUANTUM_TRANSITIONING: "transitioning",
            QuantumLabel.FULLY_QUANTUM_SAFE:    "safe",
        }[s.label]

        label_icon = {
            QuantumLabel.QUANTUM_VULNERABLE:    "🔴",
            QuantumLabel.QUANTUM_TRANSITIONING: "🟡",
            QuantumLabel.FULLY_QUANTUM_SAFE:    "🟢",
        }[s.label]

        score_color = (
            "#ff4444" if s.total_score >= 60 else
            "#ffaa00" if s.total_score >= 21 else "#00cc66"
        )

        # Score bar segments
        score_bars = ""
        components = [
            ("Key Exchange", s.key_exchange_score,  0.40),
            ("Signature",    s.signature_score,     0.25),
            ("TLS Version",  s.tls_version_score,   0.20),
            ("Key Size",     s.key_size_penalty,    0.10),
            ("Validity",     s.cert_validity_score, 0.05),
        ]
        for comp_name, comp_score, weight in components:
            bar_color = "#ff4444" if comp_score >= 70 else "#ffaa00" if comp_score >= 40 else "#00cc66"
            score_bars += f"""
            <div class="score-row">
                <span class="score-label">{comp_name}</span>
                <div class="score-bar-track">
                    <div class="score-bar-fill" style="width:{comp_score}%; background:{bar_color}"></div>
                </div>
                <span class="score-val">{comp_score}</span>
                <span class="score-weight">×{weight}</span>
            </div>"""

        # Findings
        findings_html = ""
        for finding in s.findings[:5]:
            findings_html += f'<div class="finding">{finding}</div>'

        # Remediations
        rems_html = ""
        if s.remediations and not s.is_pqc_ready:
            for i, rem in enumerate(s.remediations[:3], 1):
                rems_html += f'<div class="remediation"><span class="rem-num">{i}</span>{rem}</div>'

        # PQC Certificate banner
        cert_banner = ""
        if s.certificate_awarded:
            pqc_algos = ", ".join(s.pqc_algorithms_detected) if s.pqc_algorithms_detected else "NIST PQC"
            cert_banner = f"""
            <div class="pqc-cert-banner">
                <div class="pqc-cert-seal">🏆</div>
                <div class="pqc-cert-text">
                    <div class="pqc-cert-title">{s.certificate_awarded}</div>
                    <div class="pqc-cert-algo">Algorithms: {pqc_algos}</div>
                </div>
            </div>"""

        vpn_badge = '<span class="vpn-badge">⚠️ HNDL TARGET</span>' if s.is_vpn else ""

        asset_cards += f"""
        <div class="asset-card {label_class}" id="asset-{s.host.replace('.', '-')}-{s.port}">
            <div class="asset-header">
                <div class="asset-identity">
                    <span class="asset-icon">{label_icon}</span>
                    <div>
                        <div class="asset-host">{s.host}<span class="asset-port">:{s.port}</span></div>
                        <div class="asset-service">{s.service} {vpn_badge}</div>
                    </div>
                </div>
                <div class="asset-score-circle" style="border-color:{score_color}; color:{score_color}">
                    <div class="score-num">{s.total_score}</div>
                    <div class="score-max">/100</div>
                </div>
            </div>

            {cert_banner}

            <div class="asset-body">
                <div class="score-breakdown">
                    <div class="breakdown-title">Risk Score Breakdown</div>
                    {score_bars}
                    <div class="hndl-note">HNDL Multiplier: {s.hndl_multiplier}x</div>
                </div>

                <div class="findings-section">
                    <div class="section-title">Findings</div>
                    {findings_html if findings_html else '<div class="finding">No critical findings</div>'}
                </div>

                {f'<div class="remediation-section"><div class="section-title">Remediation Actions</div>{rems_html}</div>' if rems_html else ''}
            </div>
        </div>"""

    # Full HTML
    scan_time = datetime.now().strftime("%B %d, %Y at %H:%M UTC")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quantum Security Scan — {target_domain}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:         #050810;
    --bg2:        #080d1a;
    --panel:      #0c1220;
    --border:     #1a2540;
    --accent:     #00e5ff;
    --accent2:    #7b2fff;
    --red:        #ff4444;
    --yellow:     #ffaa00;
    --green:      #00cc66;
    --text:       #c8d8f0;
    --text-dim:   #4a6080;
    --mono:       'Space Mono', monospace;
    --sans:       'Syne', sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }}

  /* ── Animated grid background ── */
  body::before {{
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none; z-index: 0;
  }}

  .container {{ max-width: 1200px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }}

  /* ── Header ── */
  header {{
    padding: 48px 0 32px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 40px;
  }}
  .header-top {{
    display: flex; align-items: flex-start;
    justify-content: space-between; gap: 24px;
  }}
  .header-eyebrow {{
    font-family: var(--mono); font-size: 11px;
    color: var(--accent); letter-spacing: 3px;
    text-transform: uppercase; margin-bottom: 10px;
  }}
  h1 {{
    font-size: clamp(28px, 4vw, 48px);
    font-weight: 800; line-height: 1.1;
    background: linear-gradient(135deg, #fff 0%, var(--accent) 60%, var(--accent2) 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
  }}
  .header-meta {{
    font-family: var(--mono); font-size: 12px;
    color: var(--text-dim); margin-top: 12px;
  }}
  .header-meta span {{ color: var(--accent); }}
  .threat-badge {{
    background: rgba(255,68,68,0.1); border: 1px solid rgba(255,68,68,0.3);
    border-radius: 8px; padding: 12px 20px; text-align: right; flex-shrink: 0;
  }}
  .threat-label {{ font-size: 10px; letter-spacing: 2px; color: var(--red); text-transform: uppercase; }}
  .threat-score {{ font-size: 40px; font-weight: 800; color: var(--red); line-height: 1; }}
  .threat-sub {{ font-family: var(--mono); font-size: 10px; color: var(--text-dim); }}

  /* ── Summary grid ── */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px; margin-bottom: 40px;
  }}
  .stat-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px; padding: 20px;
    position: relative; overflow: hidden;
    transition: border-color 0.2s;
  }}
  .stat-card::before {{
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
  }}
  .stat-card.red::before   {{ background: var(--red); }}
  .stat-card.yellow::before {{ background: var(--yellow); }}
  .stat-card.green::before  {{ background: var(--green); }}
  .stat-card.blue::before   {{ background: var(--accent); }}
  .stat-card.purple::before {{ background: var(--accent2); }}
  .stat-label {{ font-size: 11px; letter-spacing: 1px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 8px; }}
  .stat-value {{ font-size: 36px; font-weight: 800; line-height: 1; }}
  .stat-card.red .stat-value    {{ color: var(--red); }}
  .stat-card.yellow .stat-value {{ color: var(--yellow); }}
  .stat-card.green .stat-value  {{ color: var(--green); }}
  .stat-card.blue .stat-value   {{ color: var(--accent); }}
  .stat-card.purple .stat-value {{ color: var(--accent2); }}
  .stat-sub {{ font-family: var(--mono); font-size: 10px; color: var(--text-dim); margin-top: 4px; }}

  /* ── HNDL warning ── */
  .hndl-alert {{
    background: rgba(255,68,68,0.06);
    border: 1px solid rgba(255,68,68,0.25);
    border-left: 3px solid var(--red);
    border-radius: 8px; padding: 16px 20px;
    margin-bottom: 40px;
    display: {'flex' if vpn_count > 0 else 'none'};
    align-items: center; gap: 16px;
  }}
  .hndl-icon {{ font-size: 28px; }}
  .hndl-title {{ font-weight: 700; color: var(--red); font-size: 14px; }}
  .hndl-desc {{ font-family: var(--mono); font-size: 11px; color: var(--text-dim); margin-top: 4px; }}

  /* ── Filter bar ── */
  .filter-bar {{
    display: flex; gap: 8px; margin-bottom: 24px; flex-wrap: wrap;
  }}
  .filter-btn {{
    font-family: var(--mono); font-size: 11px; letter-spacing: 1px;
    text-transform: uppercase; padding: 8px 16px;
    border-radius: 6px; border: 1px solid var(--border);
    background: var(--panel); color: var(--text-dim);
    cursor: pointer; transition: all 0.15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent); color: var(--accent);
    background: rgba(0,229,255,0.08);
  }}
  .filter-btn.red.active   {{ border-color:var(--red);    color:var(--red);    background:rgba(255,68,68,0.08); }}
  .filter-btn.yellow.active{{ border-color:var(--yellow); color:var(--yellow); background:rgba(255,170,0,0.08); }}
  .filter-btn.green.active {{ border-color:var(--green);  color:var(--green);  background:rgba(0,204,102,0.08); }}

  /* ── Asset cards ── */
  .assets-section {{ margin-bottom: 60px; }}
  .section-heading {{
    font-size: 13px; font-family: var(--mono);
    letter-spacing: 2px; text-transform: uppercase;
    color: var(--text-dim); margin-bottom: 16px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }}

  .asset-card {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; margin-bottom: 16px; overflow: hidden;
    transition: border-color 0.2s, transform 0.2s;
    animation: fadeUp 0.4s ease both;
  }}
  .asset-card:hover {{ transform: translateY(-2px); }}
  .asset-card.vulnerable   {{ border-color: rgba(255,68,68,0.2); }}
  .asset-card.transitioning {{ border-color: rgba(255,170,0,0.2); }}
  .asset-card.safe          {{ border-color: rgba(0,204,102,0.2); }}
  .asset-card.vulnerable:hover   {{ border-color: var(--red); }}
  .asset-card.transitioning:hover {{ border-color: var(--yellow); }}
  .asset-card.safe:hover          {{ border-color: var(--green); }}

  @keyframes fadeUp {{
    from {{ opacity:0; transform:translateY(12px); }}
    to   {{ opacity:1; transform:translateY(0); }}
  }}

  .asset-header {{
    display: flex; align-items: center;
    justify-content: space-between;
    padding: 20px 24px; gap: 16px;
    border-bottom: 1px solid var(--border);
  }}
  .asset-identity {{ display: flex; align-items: center; gap: 14px; }}
  .asset-icon {{ font-size: 22px; }}
  .asset-host {{ font-size: 16px; font-weight: 700; color: #fff; }}
  .asset-port {{ font-family: var(--mono); font-size: 13px; color: var(--text-dim); }}
  .asset-service {{ font-family: var(--mono); font-size: 11px; color: var(--text-dim); margin-top: 2px; }}
  .vpn-badge {{
    background: rgba(255,68,68,0.15); border: 1px solid rgba(255,68,68,0.4);
    border-radius: 4px; padding: 2px 6px; font-size: 10px; color: var(--red);
    margin-left: 8px; letter-spacing: 0.5px;
  }}

  .asset-score-circle {{
    width: 64px; height: 64px; border-radius: 50%;
    border: 2px solid; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    flex-shrink: 0; background: rgba(0,0,0,0.3);
  }}
  .score-num {{ font-size: 18px; font-weight: 800; line-height: 1; }}
  .score-max {{ font-family: var(--mono); font-size: 9px; color: var(--text-dim); }}

  /* ── PQC Certificate Banner ── */
  .pqc-cert-banner {{
    display: flex; align-items: center; gap: 16px;
    background: linear-gradient(135deg, rgba(0,204,102,0.08), rgba(0,229,255,0.05));
    border-bottom: 1px solid rgba(0,204,102,0.2);
    padding: 14px 24px;
  }}
  .pqc-cert-seal {{ font-size: 28px; }}
  .pqc-cert-title {{ font-weight: 700; color: var(--green); font-size: 13px; }}
  .pqc-cert-algo {{ font-family: var(--mono); font-size: 10px; color: var(--text-dim); margin-top: 2px; }}

  /* ── Asset body ── */
  .asset-body {{
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 0; padding: 0;
  }}
  @media (max-width: 700px) {{ .asset-body {{ grid-template-columns: 1fr; }} }}

  .score-breakdown, .findings-section, .remediation-section {{
    padding: 20px 24px;
    border-right: 1px solid var(--border);
  }}
  .remediation-section {{ border-right: none; }}
  .findings-section {{ border-right: none; }}

  .breakdown-title, .section-title {{
    font-size: 10px; font-family: var(--mono);
    letter-spacing: 2px; text-transform: uppercase;
    color: var(--text-dim); margin-bottom: 12px;
  }}

  .score-row {{
    display: flex; align-items: center; gap: 8px;
    margin-bottom: 7px; font-family: var(--mono); font-size: 11px;
  }}
  .score-label {{ width: 100px; color: var(--text-dim); flex-shrink: 0; }}
  .score-bar-track {{
    flex: 1; height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px; overflow: hidden;
  }}
  .score-bar-fill {{ height: 100%; border-radius: 2px; transition: width 1s ease; }}
  .score-val {{ width: 28px; text-align: right; color: var(--text); }}
  .score-weight {{ width: 32px; color: var(--text-dim); font-size: 9px; }}
  .hndl-note {{
    margin-top: 10px; font-family: var(--mono); font-size: 10px;
    color: var(--text-dim); padding-top: 8px; border-top: 1px solid var(--border);
  }}

  .finding {{
    font-family: var(--mono); font-size: 11px; color: var(--text);
    padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
    line-height: 1.5;
  }}
  .finding:last-child {{ border-bottom: none; }}

  .remediation {{
    display: flex; gap: 10px; align-items: flex-start;
    font-family: var(--mono); font-size: 11px; color: var(--text);
    padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
    line-height: 1.5;
  }}
  .rem-num {{
    background: var(--accent2); color: #fff; width: 18px; height: 18px;
    border-radius: 50%; display: flex; align-items: center; justify-content: center;
    font-size: 9px; flex-shrink: 0; margin-top: 1px;
  }}

  /* ── CBOM JSON section ── */
  .cbom-section {{ margin-bottom: 60px; }}
  .cbom-box {{
    background: #020408; border: 1px solid var(--border);
    border-radius: 8px; padding: 20px;
    font-family: var(--mono); font-size: 11px; color: #4a9;
    max-height: 300px; overflow-y: auto; white-space: pre;
  }}

  /* ── Footer ── */
  footer {{
    border-top: 1px solid var(--border);
    padding: 32px 0; text-align: center;
    font-family: var(--mono); font-size: 11px; color: var(--text-dim);
  }}
  footer span {{ color: var(--accent); }}

  /* ── Hidden filter ── */
  .asset-card.hidden {{ display: none; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header>
    <div class="header-top">
      <div>
        <div class="header-eyebrow">⬡ Quantum Security Audit Report</div>
        <h1>Cryptographic<br>Bill of Materials</h1>
        <div class="header-meta">
          Target: <span>{target_domain}</span> &nbsp;|&nbsp;
          Scanned: <span>{scan_time}</span> &nbsp;|&nbsp;
          Assets: <span>{total}</span>
        </div>
      </div>
      <div class="threat-badge">
        <div class="threat-label">Avg Risk Score</div>
        <div class="threat-score">{avg_score}</div>
        <div class="threat-sub">/100</div>
      </div>
    </div>
  </header>

  <!-- Summary Stats -->
  <div class="summary-grid">
    <div class="stat-card blue">
      <div class="stat-label">Total Assets</div>
      <div class="stat-value">{total}</div>
      <div class="stat-sub">internet-exposed</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">Vulnerable</div>
      <div class="stat-value">{vulnerable}</div>
      <div class="stat-sub">quantum-broken ciphers</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-label">Transitioning</div>
      <div class="stat-value">{transitioning}</div>
      <div class="stat-sub">partial migration</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Quantum Safe</div>
      <div class="stat-value">{safe}</div>
      <div class="stat-sub">NIST PQC confirmed</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">PQC Certs</div>
      <div class="stat-value">{pqc_certs}</div>
      <div class="stat-sub">certificates awarded</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">VPN / HNDL</div>
      <div class="stat-value">{vpn_count}</div>
      <div class="stat-sub">high-priority targets</div>
    </div>
  </div>

  <!-- HNDL Alert -->
  <div class="hndl-alert">
    <div class="hndl-icon">🎯</div>
    <div>
      <div class="hndl-title">HARVEST NOW, DECRYPT LATER (HNDL) — {vpn_count} VPN Endpoint(s) Detected</div>
      <div class="hndl-desc">Nation-state adversaries are actively harvesting encrypted VPN traffic today for decryption when Cryptanalytically Relevant Quantum Computers (CRQCs) arrive (~2030-2035). Immediate remediation required.</div>
    </div>
  </div>

  <!-- Asset Cards -->
  <div class="assets-section">
    <div class="section-heading">Asset Inventory — Sorted by Risk Score</div>

    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterAssets('all', this)">All ({total})</button>
      <button class="filter-btn red"    onclick="filterAssets('vulnerable', this)">🔴 Vulnerable ({vulnerable})</button>
      <button class="filter-btn yellow" onclick="filterAssets('transitioning', this)">🟡 Transitioning ({transitioning})</button>
      <button class="filter-btn green"  onclick="filterAssets('safe', this)">🟢 Safe ({safe})</button>
    </div>

    <div id="asset-list">
      {asset_cards}
    </div>
  </div>

  <!-- CBOM JSON Export -->
  <div class="cbom-section">
    <div class="section-heading">Cryptographic Bill of Materials — JSON Export</div>
    <div class="cbom-box" id="cbom-json">{json.dumps(cbom_export[:3], indent=2)}</div>
    <div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-top:8px;">
      Full export saved to: <span style="color:var(--accent)">{cbom_path}</span>
    </div>
  </div>

  <footer>
    Generated by <span>Quantum Scanner</span> &nbsp;·&nbsp;
    NIST FIPS 203/204/205 Reference &nbsp;·&nbsp;
    <span>{scan_time}</span>
  </footer>

</div>

<script>
function filterAssets(type, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.asset-card').forEach(card => {{
    if (type === 'all' || card.classList.contains(type)) {{
      card.classList.remove('hidden');
    }} else {{
      card.classList.add('hidden');
    }}
  }});
}}

// Animate score bars on load
window.addEventListener('load', () => {{
  document.querySelectorAll('.score-bar-fill').forEach(bar => {{
    const w = bar.style.width;
    bar.style.width = '0';
    setTimeout(() => {{ bar.style.width = w; }}, 200);
  }});
}});
</script>
</body>
</html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  Report saved : {report_path}")
    print(f"  CBOM JSON    : {cbom_path}")
    return report_path


# ── Test Runner ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/home/claude/quantum_scanner')

    from core.risk_scorer import calculate_risk_score, score_cbom, QuantumLabel

    mock_cbom = [
        {
            "host": "www.bank.com",        "port": 443,  "service": "HTTPS",   "is_vpn": False,
            "hndl_multiplier": 1.0,        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_algorithm": "RSAPublicKey","signature_algorithm": "sha256_with_rsa_encryption",
            "tls_version": "TLSv1.2",      "key_size": 2048, "days_left": 180,  "is_expired": False,
        },
        {
            "host": "api.bank.com",         "port": 443,  "service": "HTTPS",  "is_vpn": False,
            "hndl_multiplier": 1.0,         "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_algorithm": "EllipticCurvePublicKey","signature_algorithm": "ecdsa_with_sha256",
            "tls_version": "TLSv1.3",       "key_size": 256, "days_left": 45,   "is_expired": False,
        },
        {
            "host": "vpn.bank.com",         "port": 1194, "service": "OpenVPN","is_vpn": True,
            "hndl_multiplier": 2.0,         "cipher_suite": "DHE_RSA_AES256",
            "key_algorithm": "RSAPublicKey","signature_algorithm": "sha256_with_rsa_encryption",
            "tls_version": "TLSv1.2",       "key_size": 2048, "days_left": 300, "is_expired": False,
        },
        {
            "host": "legacy.bank.com",      "port": 443,  "service": "HTTPS",  "is_vpn": False,
            "hndl_multiplier": 1.0,         "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "key_algorithm": "RSAPublicKey","signature_algorithm": "sha256_with_rsa_encryption",
            "tls_version": "TLSv1.0",       "key_size": 1024, "days_left": -5,  "is_expired": True,
        },
        {
            "host": "pqc.bank.com",         "port": 443,  "service": "HTTPS",  "is_vpn": False,
            "hndl_multiplier": 1.0,         "cipher_suite": "TLS_ML-KEM-768_AES_256_GCM_SHA384",
            "key_algorithm": "ML-DSA-65",   "signature_algorithm": "ML-DSA-65",
            "tls_version": "TLSv1.3",       "key_size": 0, "days_left": 365,   "is_expired": False,
        },
    ]

    scored = score_cbom(mock_cbom)
    report_path = generate_report(scored, "bank.com", output_dir="/home/claude/quantum_scanner/reports")
    print(f"\n  Open in browser: file://{report_path}")
