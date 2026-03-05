export const demos = [
  {
    id: 'sc-diff',
    label: 'SBOM Diff',
    title: 'vulnex sbom diff old-bom.json new-bom.json',
    html: `<span class="t-prompt">$</span> <span class="t-cmd">vulnex sbom diff</span> <span class="t-value">old-bom.json new-bom.json</span>

<span class="t-critical">+ ADDED (2 vulnerabilities)</span>
  <span class="t-accent">flask 0.12.0</span> <span class="t-dim">(PyPI)</span>
    GHSA-562c-5r94-xh97   <span class="t-high">HIGH</span>      0.12.3   Flask is vulnerable to...
    GHSA-5wv5-4vpf-pj6m   <span class="t-high">HIGH</span>      1.0      Directory traversal i...

<span class="t-green">- REMOVED (1 vulnerability)</span>
  <span class="t-accent">lodash 4.17.20</span> <span class="t-dim">(npm)</span>
    GHSA-35jh-r3h4-6jhm   <span class="t-high">HIGH</span>      4.17.21  Command Injection in ...

<span class="t-dim">= UNCHANGED (55 vulnerabilities)</span>
  <span class="t-accent">django 3.2.0</span> <span class="t-dim">(PyPI)</span>
    GHSA-2gwj-7jmv-h26r   <span class="t-critical">CRITICAL</span>  2.2.28   SQL Injection in Django

<span class="t-dim">Summary: old=3 components (56 vulns), new=4 components (57 vulns)</span>
  <span class="t-critical">+2 added</span>  <span class="t-green">-1 removed</span>`,
  },
  {
    id: 'sc-lockfile',
    label: 'Lockfile Scan',
    title: 'vulnex scan pnpm-lock.yaml',
    html: `<span class="t-prompt">$</span> <span class="t-cmd">vulnex scan</span> <span class="t-value">pnpm-lock.yaml</span>
<span class="t-dim">Parsed 847 components from pnpm-lock.yaml</span>
<span class="t-dim">Querying OSV for 847 components...</span>
<span class="t-dim">Found 4 vulnerabilities</span>

<span class="t-accent">postcss 8.4.14</span> <span class="t-dim">(npm)</span>
  <span class="t-dim">ID                        Severity  Fixed    Summary</span>
  GHSA-7fh5-64p2-3v2j      <span class="t-medium">MEDIUM</span>    8.4.31   Parsing error in PostCSS

<span class="t-accent">semver 6.3.0</span> <span class="t-dim">(npm)</span>
  GHSA-c2qf-rxjj-qqgw      <span class="t-medium">MEDIUM</span>    6.3.1    semver vuln to ReDoS

<span class="t-dim">Summary: 847 components scanned, 2 vulnerable, 4 findings</span>
  <span class="t-medium">MEDIUM: 4</span>
<span class="t-dim">Completed in 1.203s</span>`,
  },
  {
    id: 'sc-scoring',
    label: 'Scoring',
    title: 'vulnex enrich CVE-2024-24790 --scoring-profile default',
    html: `<span class="t-prompt">$</span> <span class="t-cmd">vulnex enrich</span> <span class="t-cve">CVE-2024-24790</span> <span class="t-flag">--scoring-profile default</span>

 <span class="t-label">CVE ID:</span>         <span class="t-accent">CVE-2024-24790</span>
 <span class="t-label">Severity:</span>       <span class="t-critical">CRITICAL</span>
 <span class="t-label">CVSS Score:</span>     <span class="t-critical">9.8 (v3.1)</span>
 <span class="t-label">EPSS Score:</span>     <span class="t-value">0.00197 (percentile: 0.5715)</span>
 <span class="t-label">KEV:</span>            No

 <span class="t-label">Risk Priority:</span>  <span class="t-p0">P1-HIGH</span> (score: 65/100)
 <span class="t-label">Rationale:</span>      High CVSS but low exploitation probability
 <span class="t-label">Weighted Score:</span> <span class="t-value">30.4/100</span> <span class="t-dim">(profile: default, weights: CVSS=0.30 EPSS=0.50 KEV=0.20)</span>

<span class="t-dim"># Compare with exploit-focused profile</span>
<span class="t-prompt">$</span> <span class="t-cmd">vulnex enrich</span> <span class="t-cve">CVE-2024-24790</span> <span class="t-flag">--scoring-profile exploit-focused</span>
 <span class="t-label">Weighted Score:</span> <span class="t-value">11.0/100</span> <span class="t-dim">(profile: exploit-focused, weights: CVSS=0.10 EPSS=0.60 KEV=0.30)</span>`,
  },
  {
    id: 'sc-exploit',
    label: 'Exploit Check',
    title: 'vulnex exploit check CVE-2021-44228',
    html: `<span class="t-prompt">$</span> <span class="t-cmd">vulnex exploit check</span> <span class="t-cve">CVE-2021-44228</span>

<span class="t-accent">CVE-2021-44228</span> — 8 known exploit(s)

  <span class="t-dim">SOURCE       NAME                                          URL</span>
  github       kozmer/log4j-shell-poc <span class="t-dim">(1.2k)</span>                 <span class="t-dim">https://github.com/kozmer/log4j-shell-poc</span>
  github       fullhunt/log4j-scan <span class="t-dim">(3.1k)</span>                    <span class="t-dim">https://github.com/fullhunt/log4j-scan</span>
  metasploit   exploit/multi/http/log4shell_header_injection  <span class="t-dim">https://github.com/rapid7/...</span>
  nuclei       http/cves/2021/cve-2021-44228.yaml            <span class="t-dim">https://github.com/projectdiscovery/...</span>
  exploitdb    50592                                          <span class="t-dim">https://www.exploit-db.com/exploits/50592</span>

<span class="t-dim">Sources:</span> GitHub (5) · Metasploit (2) · Nuclei (1) · ExploitDB (1)`,
  },
  {
    id: 'sc-ignore',
    label: 'Suppress',
    title: 'vulnex sbom check bom.json',
    html: `<span class="t-dim"># .vulnexignore — suppress accepted risks</span>
<span class="t-prompt">$</span> cat <span class="t-value">.vulnexignore</span>
<span class="y-key">suppressions:</span>
  - <span class="y-key">id:</span> <span class="y-str">GHSA-2gwj-7jmv-h26r</span>
    <span class="y-key">package:</span> <span class="y-str">django</span>
    <span class="y-key">reason:</span> <span class="y-str">"Transitive dep, mitigated at WAF"</span>
    <span class="y-key">expires:</span> <span class="y-str">"2026-06-01"</span>

<span class="t-prompt">$</span> <span class="t-cmd">vulnex sbom check</span> <span class="t-value">bom.json</span>
<span class="t-dim">Suppressed 1 findings via .vulnexignore</span>
<span class="t-dim">Found 2 vulnerabilities</span>

<span class="t-accent">lodash 4.17.20</span> <span class="t-dim">(npm)</span>
  GHSA-35jh-r3h4-6jhm      <span class="t-high">HIGH</span>      4.17.21  Command Injection in ...

<span class="t-dim">Summary: 3 components scanned, 1 vulnerable, 2 findings</span>
  <span class="t-high">HIGH: 2</span>
  Suppressed: 1 (use --strict to show all)`,
  },
  {
    id: 'sc-pipe',
    label: 'Piping',
    title: 'vulnex — piping & composition',
    html: `<span class="t-dim"># Recent KEV entries → enrich → JSON</span>
<span class="t-prompt">$</span> <span class="t-cmd">vulnex kev recent</span> <span class="t-flag">--days 7 -o csv</span> \\
    | cut -d, -f1 \\
    | <span class="t-cmd">vulnex enrich</span> <span class="t-flag">--stdin -o json</span>

<span class="t-dim"># Bulk EPSS scoring from a file</span>
<span class="t-prompt">$</span> cat cves.txt \\
    | <span class="t-cmd">vulnex epss score</span> <span class="t-flag">--stdin -o csv</span> \\
    > scores.csv

<span class="t-dim"># Offline mode after warming cache</span>
<span class="t-prompt">$</span> <span class="t-cmd">vulnex enrich</span> <span class="t-cve">CVE-2021-44228</span>
<span class="t-prompt">$</span> <span class="t-cmd">vulnex</span> <span class="t-flag">--offline</span> <span class="t-cmd">enrich</span> <span class="t-cve">CVE-2021-44228</span>`,
  },
];
