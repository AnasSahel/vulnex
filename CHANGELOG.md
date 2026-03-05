# Changelog

## [1.4.0](https://github.com/AnasSahel/vulnex/compare/v1.3.0...v1.4.0) (2026-03-05)


### Features

* add policy engine, scanner parsers, and init command ([0b427ab](https://github.com/AnasSahel/vulnex/commit/0b427ab752522dc8e094a4938bd1fb0a70018b24))
* **cache:** wire up caching for NVD, EPSS, GHSA, and OSV clients ([4930282](https://github.com/AnasSahel/vulnex/commit/4930282489d8d715dc0b29af2542ed19f8e9c1a7))
* **cve:** add styled output for cve history command ([296f411](https://github.com/AnasSahel/vulnex/commit/296f411cf22c350a8aad4d5ae0af5d48188fdfaa))
* **cve:** add styled output for cve watch command ([acc1b31](https://github.com/AnasSahel/vulnex/commit/acc1b31608937baef9cacfe7d0f357aa90b4c74f))
* **cve:** display references, affected versions, and last modified date ([6d57d05](https://github.com/AnasSahel/vulnex/commit/6d57d050a07c869a9b1135d9a8f6f3b30211d63f))
* **sbom:** add --enrich flag for EPSS/KEV/exploit enrichment of scan findings ([1696e4d](https://github.com/AnasSahel/vulnex/commit/1696e4dd446fb6c78661afc4497ee110df276dab))
* **website:** add CVE command documentation page ([b9472c1](https://github.com/AnasSahel/vulnex/commit/b9472c1113e85c5d8b16917bddc49c13c43f9e28))
* **website:** add scoring and prioritization documentation page ([d4df48b](https://github.com/AnasSahel/vulnex/commit/d4df48b1dac55eec9b863f2514004763068284c5))
* **website:** migrate to Astro with light/dark mode support ([86aede6](https://github.com/AnasSahel/vulnex/commit/86aede6d837a07b3e47e125ad791ccca1118a09d))


### Bug Fixes

* **nvd:** uppercase cvssV3Severity parameter for NVD API ([7ad7457](https://github.com/AnasSahel/vulnex/commit/7ad7457017b3c7a6d5ca0ac2812f686291142b41))
* **website:** add base path for GitHub Pages deployment ([70a2ce3](https://github.com/AnasSahel/vulnex/commit/70a2ce31b7b354ba9b7b1825f9f714c8d789aeba))
* **website:** escape HTML entities in CVE docs version range ([b473455](https://github.com/AnasSahel/vulnex/commit/b4734552eb56e058ee785acb658efcee28d34b71))

## [1.3.0](https://github.com/AnasSahel/vulnex/compare/v1.2.1...v1.3.0) (2026-03-04)


### Features

* **exploit:** add exploit check command with multi-source intelligence ([69b3312](https://github.com/AnasSahel/vulnex/commit/69b33123050bbd4a8f3fe95499781a8700817082))
* **exploit:** add exploit check command with multi-source intelligence ([#9](https://github.com/AnasSahel/vulnex/issues/9)) ([4b92811](https://github.com/AnasSahel/vulnex/commit/4b928117e9eaff45b86c63af68bd04f9537fae88))
* **output:** add SARIF v2.1.0 output format ([8f59f3a](https://github.com/AnasSahel/vulnex/commit/8f59f3a92ffcec4f7cb4b1814bd16b6b6fb670f5))
* **sbom:** add .vulnexignore suppression file support ([#8](https://github.com/AnasSahel/vulnex/issues/8)) ([c78bab4](https://github.com/AnasSahel/vulnex/commit/c78bab476212b8f7132068e90385ca5cd6e197a1))
* **sbom:** add lockfile scanning with batch OSV queries ([8d78ad1](https://github.com/AnasSahel/vulnex/commit/8d78ad10ac0fd565ff833486ae3cab57e0b1c930))
* **scoring:** add configurable scoring profiles and weighted composite scores ([ed774d3](https://github.com/AnasSahel/vulnex/commit/ed774d36aaf68db16e9f72d57b7a1aedf799476b))
* **website:** replace showcase grid with tabbed terminal view ([8d12af1](https://github.com/AnasSahel/vulnex/commit/8d12af1ae5116bd91e620b547db73a704a15ea0e))


### Bug Fixes

* **docs:** align website and README terminal outputs with actual CLI format ([cf8935d](https://github.com/AnasSahel/vulnex/commit/cf8935d9aa44743b76f674e91a8c3ad340a50258))
* **website:** constrain install panel overflow ([324c0b5](https://github.com/AnasSahel/vulnex/commit/324c0b563a6cee0ad8aed9aa56562809a3e1cd9f))
* **website:** prevent install panel command from overflowing ([d3a125a](https://github.com/AnasSahel/vulnex/commit/d3a125a33c9e36877cbc0642511d6d12d32d419c))
* **website:** prevent showcase terminal cards from overlapping ([61680fc](https://github.com/AnasSahel/vulnex/commit/61680fc87e526f90ed9becd43197e559f863e2b8))
* **website:** restore showcase grid gap between terminal cards ([1cc2a5b](https://github.com/AnasSahel/vulnex/commit/1cc2a5b3c8b8b36cc9741cb416ee8be3b5074eea))
* **website:** stack showcase terminals in single column ([7c92dcf](https://github.com/AnasSahel/vulnex/commit/7c92dcf1b8a18da4a8d03509dc06a91fcb474727))
* **website:** use minmax(0, 1fr) for showcase grid tracks ([6fd87f2](https://github.com/AnasSahel/vulnex/commit/6fd87f206f0e759471a48e407fdd015f8435e1d8))
* **website:** wrap long curl command in binary install tab ([7c235b0](https://github.com/AnasSahel/vulnex/commit/7c235b0724e9cab4169c259143e81c64a7524e32))

## [1.2.1](https://github.com/AnasSahel/vulnex/compare/v1.2.0...v1.2.1) (2026-03-03)


### Bug Fixes

* **kev:** guard cache calls to prevent nil-pointer panic with --no-cache ([6fc6cc9](https://github.com/AnasSahel/vulnex/commit/6fc6cc9baa33202cdfbda01e44e11fe1b987c3dc))
* **osv:** propagate errors and fetch sibling aliases in QueryByCVE ([6b152e4](https://github.com/AnasSahel/vulnex/commit/6b152e439dc0177a910ebe730fec8b0663c70748))

## [1.2.0](https://github.com/AnasSahel/vulnex/compare/v1.1.0...v1.2.0) (2026-03-03)


### Features

* **sbom:** add diff command to compare SBOM vulnerability changes ([950d9cb](https://github.com/AnasSahel/vulnex/commit/950d9cb510eee22dc6a259907e2a88ffa1bcd40e))

## [1.1.0](https://github.com/AnasSahel/vulnex/compare/v1.0.0...v1.1.0) (2026-03-02)


### Features

* **output:** add rich formatted display for advisory get ([7f7c6f8](https://github.com/AnasSahel/vulnex/commit/7f7c6f8708d281f9aeca4791df1c8a1a094df055))
* **sbom:** improve check output with component grouping, severity fix, and exit code ([f3f5076](https://github.com/AnasSahel/vulnex/commit/f3f507691b90dee039afc5b1fdcc2516d2eaf0a9))


### Bug Fixes

* **build:** add Formula directory to goreleaser Homebrew config ([4170ff3](https://github.com/AnasSahel/vulnex/commit/4170ff323c91fa669cb2ce0fff31375f05c4868b))

## 1.0.0 (2026-03-02)


### Features

* differentiate cve get from enrich and improve error handling ([bca6c21](https://github.com/AnasSahel/vulnex/commit/bca6c219ad3f89dd29a6c5d276c5c43d7b2b0158))
* implement full vulnex CLI with multi-source vulnerability intelligence ([00a9f75](https://github.com/AnasSahel/vulnex/commit/00a9f7517d9779c08b6fe5095079b53c6f978d0d))
* **output:** add --long flag and sort CVE results newest-first ([f066854](https://github.com/AnasSahel/vulnex/commit/f06685437218ea38028b2f94811c8a55f2d4da55))


### Bug Fixes

* **ci:** checkout tag ref so GoReleaser finds the correct commit ([89fccc7](https://github.com/AnasSahel/vulnex/commit/89fccc7e15ef47e0f67bff12e3223edafb12b04f))
* **ci:** run GoReleaser directly in release-please workflow ([17c24ea](https://github.com/AnasSahel/vulnex/commit/17c24ead2f80438a0267f08245e5ee41c46cec41))
* **ci:** use HOMEBREW_TAP_TOKEN for cross-repo Homebrew formula push ([bdd009e](https://github.com/AnasSahel/vulnex/commit/bdd009e357d7e2629c1de3f95bc6087b4308789d))
* **ghsa:** match API type for first_patched_version field ([a2af009](https://github.com/AnasSahel/vulnex/commit/a2af009afa6cad8efa6bdda8bcf896e442e512a6))
* **nvd:** handle 120-day date range limit and print errors to stderr ([5b72524](https://github.com/AnasSahel/vulnex/commit/5b72524eca7ecff3cbb7fe6a31b1447bcc1905d6))
* use AnasSahel/homebrew-tap for Homebrew formula ([5bbccc4](https://github.com/AnasSahel/vulnex/commit/5bbccc401cf0661c222b3a211d45244d1e3fa862))

## 1.0.0 (2026-03-02)


### Features

* differentiate cve get from enrich and improve error handling ([bca6c21](https://github.com/AnasSahel/vulnex/commit/bca6c219ad3f89dd29a6c5d276c5c43d7b2b0158))
* implement full vulnex CLI with multi-source vulnerability intelligence ([00a9f75](https://github.com/AnasSahel/vulnex/commit/00a9f7517d9779c08b6fe5095079b53c6f978d0d))
* **output:** add --long flag and sort CVE results newest-first ([f066854](https://github.com/AnasSahel/vulnex/commit/f06685437218ea38028b2f94811c8a55f2d4da55))


### Bug Fixes

* **ci:** checkout tag ref so GoReleaser finds the correct commit ([89fccc7](https://github.com/AnasSahel/vulnex/commit/89fccc7e15ef47e0f67bff12e3223edafb12b04f))
* **ci:** run GoReleaser directly in release-please workflow ([17c24ea](https://github.com/AnasSahel/vulnex/commit/17c24ead2f80438a0267f08245e5ee41c46cec41))
* **ghsa:** match API type for first_patched_version field ([a2af009](https://github.com/AnasSahel/vulnex/commit/a2af009afa6cad8efa6bdda8bcf896e442e512a6))
* **nvd:** handle 120-day date range limit and print errors to stderr ([5b72524](https://github.com/AnasSahel/vulnex/commit/5b72524eca7ecff3cbb7fe6a31b1447bcc1905d6))
* use AnasSahel/homebrew-tap for Homebrew formula ([5bbccc4](https://github.com/AnasSahel/vulnex/commit/5bbccc401cf0661c222b3a211d45244d1e3fa862))

## 1.0.0 (2026-03-02)


### Features

* differentiate cve get from enrich and improve error handling ([bca6c21](https://github.com/AnasSahel/vulnex/commit/bca6c219ad3f89dd29a6c5d276c5c43d7b2b0158))
* implement full vulnex CLI with multi-source vulnerability intelligence ([00a9f75](https://github.com/AnasSahel/vulnex/commit/00a9f7517d9779c08b6fe5095079b53c6f978d0d))
* **output:** add --long flag and sort CVE results newest-first ([f066854](https://github.com/AnasSahel/vulnex/commit/f06685437218ea38028b2f94811c8a55f2d4da55))


### Bug Fixes

* **ghsa:** match API type for first_patched_version field ([a2af009](https://github.com/AnasSahel/vulnex/commit/a2af009afa6cad8efa6bdda8bcf896e442e512a6))
* **nvd:** handle 120-day date range limit and print errors to stderr ([5b72524](https://github.com/AnasSahel/vulnex/commit/5b72524eca7ecff3cbb7fe6a31b1447bcc1905d6))

## Changelog
