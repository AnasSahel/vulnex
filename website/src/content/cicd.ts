export const cicdExamples = [
  {
    id: 'ci-diff',
    label: 'Diff Gate',
    filename: '.github/workflows/security.yml',
    code: `<span class="line-number"> 1</span>  <span class="y-key">name:</span> <span class="y-str">Vulnerability Diff Gate</span>
<span class="line-number"> 2</span>  <span class="y-key">on:</span> <span class="y-str">[pull_request]</span>
<span class="line-number"> 3</span>
<span class="line-number"> 4</span>  <span class="y-key">jobs:</span>
<span class="line-number"> 5</span>    <span class="y-key">vuln-diff:</span>
<span class="line-number"> 6</span>      <span class="y-key">runs-on:</span> <span class="y-str">ubuntu-latest</span>
<span class="line-number"> 7</span>      <span class="y-key">steps:</span>
<span class="line-number"> 8</span>        - <span class="y-key">uses:</span> <span class="y-str">actions/checkout@v4</span>
<span class="line-number"> 9</span>        - <span class="y-key">name:</span> <span class="y-str">Install vulnex</span>
<span class="line-number">10</span>          <span class="y-key">run:</span> <span class="y-str">go install github.com/trustin-tech/vulnex@latest</span>
<span class="line-number">11</span>
<span class="line-number">12</span>        - <span class="y-key">name:</span> <span class="y-str">Generate SBOMs</span>
<span class="line-number">13</span>          <span class="y-key">run:</span> |
<span class="line-number">14</span>            <span class="y-str">git stash && cyclonedx-gomod app > old-bom.json</span>
<span class="line-number">15</span>            <span class="y-str">git stash pop && cyclonedx-gomod app > new-bom.json</span>
<span class="line-number">16</span>
<span class="line-number">17</span>        - <span class="y-key">name:</span> <span class="y-str">Diff for new vulnerabilities</span>
<span class="line-number">18</span>          <span class="y-key">run:</span> <span class="y-str">vulnex sbom diff old-bom.json new-bom.json</span>
<span class="line-number">19</span>          <span class="y-comment"># Exits 1 if new vulns introduced</span>
<span class="line-number">20</span>          <span class="y-comment"># Commit .vulnexignore to suppress accepted risks</span>`,
  },
  {
    id: 'ci-scan',
    label: 'Lockfile Scan',
    filename: '.github/workflows/security.yml',
    code: `<span class="line-number"> 1</span>  <span class="y-key">name:</span> <span class="y-str">Security Gate</span>
<span class="line-number"> 2</span>  <span class="y-key">on:</span> <span class="y-str">[push, pull_request]</span>
<span class="line-number"> 3</span>
<span class="line-number"> 4</span>  <span class="y-key">jobs:</span>
<span class="line-number"> 5</span>    <span class="y-key">vuln-check:</span>
<span class="line-number"> 6</span>      <span class="y-key">runs-on:</span> <span class="y-str">ubuntu-latest</span>
<span class="line-number"> 7</span>      <span class="y-key">steps:</span>
<span class="line-number"> 8</span>        - <span class="y-key">uses:</span> <span class="y-str">actions/checkout@v4</span>
<span class="line-number"> 9</span>        - <span class="y-key">name:</span> <span class="y-str">Install vulnex</span>
<span class="line-number">10</span>          <span class="y-key">run:</span> <span class="y-str">go install github.com/trustin-tech/vulnex@latest</span>
<span class="line-number">11</span>
<span class="line-number">12</span>        - <span class="y-key">name:</span> <span class="y-str">Scan lockfile for vulnerabilities</span>
<span class="line-number">13</span>          <span class="y-key">run:</span> <span class="y-str">vulnex scan go.sum --severity critical</span>
<span class="line-number">14</span>          <span class="y-comment"># Works with any lockfile: go.sum, package-lock.json,</span>
<span class="line-number">15</span>          <span class="y-comment"># yarn.lock, pnpm-lock.yaml, Cargo.lock, etc.</span>
<span class="line-number">16</span>          <span class="y-comment"># Exits 1 if critical vulns found</span>`,
  },
];
