# Local Network Recon Guide

This guide describes how to assess a local network in an authorized, low-impact way.

SignalHound currently focuses on external reconnaissance. Internal network scanning is a future epic and is not implemented in the application yet. Until that exists, local network checks should be performed manually and documented in SignalHound as observed assets, services, and findings.

## Safety Rules

- Only scan networks you own or are explicitly authorized to assess.
- Define the exact IP ranges before running any command.
- Start with passive or low-impact discovery.
- Avoid brute force, credential attacks, exploit checks, destructive tests, and high-rate scanning.
- Do not scan guest, neighbor, ISP, VPN, or third-party networks unless they are explicitly in scope.
- Record what was scanned, when, from which machine, and with which command.

## Recommended Workflow

1. Define scope.
2. Identify local network ranges.
3. Discover live hosts.
4. Detect exposed services on authorized hosts.
5. Document assets and services.
6. Run limited web finding checks where appropriate.
7. Review changes and follow up manually.

## 1. Define Scope

Write down the exact local ranges that are authorized.

Examples:

```text
192.168.1.0/24
192.168.10.0/24
10.0.0.0/24
```

Also define exclusions.

Examples:

```text
192.168.1.1        router, only basic discovery allowed
192.168.1.20       NAS, no intrusive checks
192.168.1.100-150  guest Wi-Fi range, excluded
```

SignalHound currently supports CIDR scopes in the data model, but the implemented scanner workflow is still designed around the external recon MVP. Treat internal CIDR scopes as documentation until the internal recon epic is implemented.

## 2. Identify Local Network Ranges

On macOS:

```bash
ipconfig getifaddr en0
route -n get default
ifconfig
```

On Linux:

```bash
ip addr
ip route
```

Choose the interface and subnet you actually want to assess.

## 3. Discover Live Hosts

Use a ping sweep or ARP-based discovery first.

For a typical home or lab subnet:

```bash
nmap -sn 192.168.1.0/24
```

For a quieter ARP-based local LAN discovery:

```bash
nmap -sn -PR 192.168.1.0/24
```

Expected output gives you live IP addresses and sometimes hostnames or MAC vendor hints.

Document discovered hosts as assets in SignalHound:

- `asset_type`: `IP` or `HOST`
- `source`: `manual-local-recon`
- `known_asset`: true only if the host is authorized and expected

## 4. Detect Exposed Services

Start with a small set of common ports.

```bash
nmap -Pn -n --max-retries 1 --host-timeout 60s -sV --version-intensity 2 -p 22,53,80,443,445,3389 192.168.1.10
```

For multiple known hosts:

```bash
nmap -Pn -n --max-retries 1 --host-timeout 60s -sV --version-intensity 2 -p 22,53,80,443,445,3389 192.168.1.10 192.168.1.20
```

Avoid full-port scans at the beginning. If needed later, run them only against a small approved host set:

```bash
nmap -Pn -n --max-retries 1 --host-timeout 180s -sV --version-intensity 2 -p- 192.168.1.10
```

Document open services in SignalHound:

- protocol
- port
- service name
- product/version if detected
- source command

## 5. Web Checks

If a host exposes HTTP or HTTPS, verify it manually first:

```bash
curl -I http://192.168.1.10
curl -I https://192.168.1.10
```

Then run a small, non-intrusive Nuclei template set only where authorized:

```bash
nuclei \
  -jsonl \
  -no-color \
  -disable-update-check \
  -ni \
  -follow-redirects \
  -max-redirects 3 \
  -target http://192.168.1.10 \
  -templates http/technologies/php-detect.yaml \
  -templates http/technologies/wordpress-detect.yaml \
  -templates http/exposed-panels/wordpress-login.yaml \
  -templates http/misconfiguration/xss-deprecated-header.yaml \
  -timeout 8 \
  -retries 1 \
  -concurrency 5 \
  -rate-limit 10
```

If there are no matches, record that as a completed check with zero findings. A scan with zero findings is still a useful result.

## 6. What to Record as Findings

Create a finding when there is something actionable.

Examples:

- Unintended admin interface exposed on the LAN
- HTTP service without TLS where TLS is expected
- Deprecated or risky service exposed unnecessarily
- Device with unexpected open SMB/RDP/SSH
- Default web panel visible
- Unsupported software version observed

Do not create a finding just because a host exists.

## 7. Current SignalHound Mapping

Current app support:

- Organizations
- External scopes and CIDR scope records
- Assets
- Services
- Findings
- Scanner jobs for external recon adapters
- Run output and import summaries

Not implemented yet:

- Internal scan zones
- Internal scanner nodes
- Network segmentation validation
- Internal recon automation
- Scheduled recurring internal scans

## 8. Recommended Future Epic

Add an `INTERNAL_IT` recon epic with:

- explicit internal scope creation
- local CIDR scope enforcement
- safe Nmap host discovery adapter
- safe Nmap service discovery adapter
- optional small Nuclei web profile for internal HTTP services
- scanner execution profile labels such as `local_discovery`, `local_service_discovery`, and `local_web_checks`
- clear rate limits and default timeouts
- UI warning that internal scanning is only for authorized local networks

Do not reuse the current external scanner flow blindly for internal networks. Internal recon needs its own scan-zone-aware scope checks and safer defaults.
