# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- HTML report generation
- Daemon mode for continuous monitoring
- Slack/Discord notification integration

## [3.0.0] - 2026-01-30 (OpenClawAudit)

### Added

- **Rebranding**: Renamed from MoltAudit to OpenClawAudit
- **`openclaw-security-audit.sh`**: New primary script with OpenClaw branding
- **7 new security check functions** (60+ new sub-checks):
  - `check_critical_vulnerabilities()` — **Zero-Day Audit**: Detects 8 critical vulnerabilities (RCE, SSRF, Auth Bypass, Shell Injection, etc.) from recent security research
  - `check_prompt_injection_defense()` — OWASP LLM01 checks (input sanitization, system prompt protection, content filtering, tool restrictions)
  - `check_mcp_server_security()` — MCP binding, authentication, tool allowlists
  - `check_skill_integrity()` — Plugin signatures, permissions, supply chain verification
  - `check_api_key_hygiene()` — Hardcoded keys, .env permissions, git history exposure
  - `check_session_isolation()` — Browser profile isolation, session timeouts
  - `check_openclaw_native_audit()` — Extended native audit with OpenClaw CLI support
- **OpenClaw config paths**: Support for `~/.openclaw/` directory
- **OWASP LLM Top 10 coverage**: Comprehensive prompt injection and excessive agency checks
- **MITRE ATLAS mappings**: AI-specific attack techniques (AML.T0043, etc.)
- **3 new vulnerabilities documented**:
  - MCP Server Exposure (Attack Vector #11)
  - API Key Compromise (Attack Vector #12)
  - Context Window Poisoning (Attack Vector #13)

### Changed

- Version bump to 3.0.0
- Script renamed from `molt-security-audit.sh` to `openclaw-security-audit.sh`
- Banner updated to "OpenClaw Security Audit" with compliance badges
- Config path detection now checks OpenClaw paths first, then legacy paths
- Documentation references updated to `openclaw-*` files
- Total check functions: 20 → 31
- Total sub-checks: 80+ → 130+

### Backwards Compatibility

- All existing checks preserved with updated section titles
- JSON output format unchanged

### References

- OWASP LLM Top 10: https://owasp.org/www-project-llm-ai-security/
- MITRE ATLAS: https://atlas.mitre.org/
- OpenClaw Security Docs: https://docs.openclaw.ai/gateway/security

## [2.0.0] - 2026-01-28

### Added

- **`--stig` flag** for DoD-grade DISA STIG / CIS Benchmark / NIST 800-53 controls
- **8 new check functions** (53 new sub-checks total):
  - `check_kernel_hardening()` — 8 sysctl checks (ASLR, SYN cookies, IP forwarding, etc.)
  - `check_audit_logging()` — 5 auditd checks (daemon, rules, permissions, retention, boot)
  - `check_mandatory_access()` — SELinux/AppArmor enforcement
  - `check_account_controls()` — 5 account/auth checks (TMOUT, faillock, pwquality, empty passwords, root console)
  - `check_service_hardening()` — 4 systemd checks (debug-shell, ctrl-alt-del, core dumps, service count)
  - `check_crypto_controls()` — 3 crypto checks (crypto policy, FIPS, TLS)
  - `check_file_integrity()` — 3 integrity checks (AIDE/Tripwire, world-writable, SUID/SGID)
  - `check_ai_supply_chain()` — 6 AI-specific checks (SBOM, model integrity, plugin allowlist, rate limiting, TLS, foreign model origin)
  - `check_network_zero_trust()` — 3 network checks (exposed services, encrypted DNS, segmentation)
- **4 extended existing checks**:
  - SSH: 6 new STIG sub-checks (idle timeout, host key perms, PermitUserEnvironment, ciphers, MACs)
  - Firewall: macOS ALF, Gatekeeper, SIP checks (APPL-15 STIG)
  - Docker: 4 new sub-checks (read-only rootfs, no-new-privileges, memory/CPU limits)
- **STIG compliance mapping**: `docs/STIG-MAPPING.md` with full DISA STIG ID → CIS ID → NIST 800-53 mapping
- ~102 new integration tests (9 new test files + extended existing tests)
- New test fixtures: `sshd_config-stig-secure`, `sshd_config-stig-weak`

### Changed

- Version bump to 2.0.0
- JSON output now includes `stig_mode` field
- Banner displays STIG mode indicator when enabled
- Default behavior unchanged (backwards compatible — new checks require `--stig`)

### References

- DISA RHEL 9 STIG v2 (2025-05-14)
- DISA macOS 15 Sequoia STIG v1 (2025-05-05)
- NIST AI 100-1, NIST SP 800-53 COSAiS
- FY2026 NDAA AI/ML Security Framework
- DoD Zero Trust Reference Architecture v2.0

## [1.1.0] - 2026-01-28

### Added

- Native `openclaw security audit` integration (check #11)
- `--deep` flag for extended audit including native OpenClaw checks
- Portable timeout handling for cross-platform compatibility
- 12 new integration tests for native audit checks
- OpenClaw workspace skill for running audits

### Changed

- Version bump to 1.1.0
- Test count increased from 161 to 173 (integration: 56 → 68)

## [1.0.0] - 2026-01-28

### Added

- Initial release of OpenClawAudit security audit tool
- **Security Checks**:
  - SSH security (password auth, root login, fail2ban)
  - Firewall detection (UFW, iptables, firewalld)
  - Gateway exposure (binding address, authentication)
  - User allowlists (Telegram, Discord, Slack)
  - Browser profile security (session isolation)
  - Password manager CLI detection (1Password, Bitwarden, LastPass)
  - Docker security (privileged mode, socket mounts, root user)
  - File permissions (.env, SSH keys, AWS credentials)
  - Token exposure (logs, shell history)
  - Process security (root processes, exposed tokens)
- **Output Modes**:
  - Standard colored terminal output
  - JSON output for CI/CD integration (`--json`)
  - Quiet mode for minimal output (`--quiet`)
- **Fix Mode**: Auto-fix safe issues with `--fix`
- **Risk Scoring**: 0-100 scale with severity ratings
- **Comprehensive Test Suite**: 161 tests using bats-core
  - 53 unit tests
  - 56 integration tests
  - 52 output tests
- Documentation:
  - Detailed vulnerability guide
  - Contributing guidelines
  - Security policy

### Security

- Defensive tool only - audits YOUR OWN systems
