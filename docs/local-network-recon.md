# Local Network Recon Guide

This guide describes how to assess a local network in an authorized, low-impact way.

SignalHound supports a conservative internal IT quick assessment for explicitly authorized `INTERNAL_IT` scopes. The current Docker-based scanner can identify hosts that answer reliable Nmap discovery probes, such as ICMP echo replies, and hosts with open scanned services. It is not a complete LAN inventory tool yet.

Docker Desktop can make local network discovery noisy or incomplete: some probes make every address look up, while phones, TVs, and IoT devices may block ICMP and expose no scanned TCP services. For full LAN inventory, SignalHound needs a future scanner node that runs directly on the host or inside the LAN rather than only through Docker NAT.

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
6. Fingerprint observed web services.
7. Run limited web finding checks where appropriate.
8. Review changes and follow up manually.

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

SignalHound supports active internal CIDR scopes via `scan_zone=INTERNAL_IT`. Create the scope explicitly before running an assessment. Host/CIDR inputs such as `192.168.0.1/24` are normalized to the network, for example `192.168.0.0/24`.

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

Run an `internal_it_quick` assessment from the GUI for the scoped CIDR. SignalHound imports only hosts with open services or reliable host-discovery reasons. Docker/NAT-only pseudo-up responses such as `reset`, `user-set`, and `unknown-response` without open services are ignored.

For internal targets, SignalHound checks a conservative web/admin port set: `80,443,3000,5000,7000,8000,8080,8443,9000,9443`. This is meant to catch router UIs and local Mac/dev web services without becoming a full-port scan.

If you need fuller inventory coverage, run host-based discovery outside Docker and document missing devices manually until a dedicated LAN scanner node exists.

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

## 5. Web Fingerprinting

After an internal assessment completes, use **Prepare web fingerprinting** in the assessment detail panel. SignalHound creates `web_fingerprint` jobs for observed, in-scope HTTP(S) services. Run those jobs from the Scanner jobs table before preparing vulnerability checks.

Fingerprinting records lightweight context as service-observation metadata:

- URL and HTTP status
- HTML page title
- `Server` and `Content-Type` headers
- redirect location
- TLS certificate subject, issuer, and expiry where available
- connection errors for evidence

This step is useful for routers, local Mac web services, NAS/admin panels, TV boxes, and other LAN devices with web interfaces. It does not brute-force logins or submit forms.

## 6. Web Checks

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

## 7. Mobile and OS Version Limits

Mobile operating-system versions are usually not reliably discoverable from passive LAN metadata or conservative remote probes. Treat hostname, mDNS, UPnP, or web-title hints as low-confidence context only.

Reliable mobile OS/version inventory should come from one of these future or manual sources:

- manual asset context entered by an analyst
- Apple/Android MDM export
- Microsoft Intune or another device-management provider
- a self-report workflow on the device

Do not create a confirmed outdated-OS finding from network hints alone.

## 8. What to Record as Findings

Create a finding when there is something actionable.

Examples:

- Unintended admin interface exposed on the LAN
- HTTP service without TLS where TLS is expected
- Deprecated or risky service exposed unnecessarily
- Device with unexpected open SMB/RDP/SSH
- Default web panel visible
- Unsupported software version observed

Do not create a finding just because a host exists.

## 9. Current SignalHound Mapping

Current app support:

- Organizations
- External and internal IT scopes
- Assets
- Services
- Findings
- Scanner jobs for external recon adapters
- Internal IT quick assessments with conservative Nmap import
- Assessment follow-up action to prepare scoped web-fingerprinting jobs
- Run output and import summaries

Not implemented yet:

- Internal scanner nodes
- Network segmentation validation
- Scheduled recurring internal scans
- MDM/provider-based mobile OS version inventory

## 10. Recommended Future Epic

Future internal recon work:

- local scanner node outside Docker NAT
- safe ARP/neighbor-table host discovery
- optional small Nuclei web profile for internal HTTP services
- scanner execution profile labels such as `local_discovery`, `local_service_discovery`, and `local_web_checks`
- clear rate limits and default timeouts
- UI warning that internal scanning is only for authorized local networks

Do not reuse external scanner flow blindly for internal networks. Internal recon needs scan-zone-aware scope checks, safer defaults, and a scanner placement that can actually see the LAN.
