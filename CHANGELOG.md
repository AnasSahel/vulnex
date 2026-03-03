# Changelog

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
