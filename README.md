# network-testing

A tool to check that a site's firewall allows the traffic Kargo devices need.
Run it from a machine on the same network segment as the Kargo device. The
results then match what the device will see.

Everything is in one file, `kargo_netcheck.py`. It uses only the Python
standard library, so you can copy that file to any machine with Python 3.7+
and run it.

## Quick start

```bash
python3 kargo_netcheck.py
```

This runs every check and prints a summary. Exit code `0` means all checks
passed, `2` means at least one check gave a partial result, and `1` means at
least one check failed.

To run a single check:

```bash
python3 kargo_netcheck.py dns|tcp|stun|tls [options]
python3 kargo_netcheck.py <check> -h     # options for that check
```

## Firewall requirements

These endpoints must be allowlisted and reachable:

| Endpoint                              | Protocol / Port      | Verified by        |
| ------------------------------------- | -------------------- | ------------------ |
| `8.8.8.8` (optional, see below)       | UDP 53 (DNS)         | `dns --server 8.8.8.8` |
| `54.153.23.224`                       | TCP 8022             | `tcp`              |
| `edp12.devicecloud.com`               | TCP 3199             | `tcp`, `tls`       |
| `sdn.kargo.zone` (`13.56.25.183`)     | UDP 3478 (STUN)      | `stun`             |
| `sdn.kargo.zone` (`13.56.25.183`)     | TCP 443, TCP 80      | `tcp`, `tls`       |
| `sdn.kargo.zone` (`13.56.25.183`)     | UDP 41641            | not tested         |
| `3.151.242.46`                        | UDP 41641            | not tested         |
| `54.176.130.49`                       | UDP 41641            | not tested         |

UDP 41641 is not tested. These servers don't reply to an arbitrary probe, so a
missing reply would not show whether the port is blocked.

### DNS

Allowing `8.8.8.8` on UDP 53 is optional. The site's own DNS resolver can be
used instead, as long as it returns the real public records for `kargo.zone`
and `devicecloud.com` (including subdomains) without changing them. A resolver
that rewrites, filters or sinkholes these names will break the device.

### No SSL/TLS/HTTPS inspection

Kargo devices need a direct TLS connection to the endpoints below. The
connection must not be intercepted or changed. Turn off SSL/TLS/HTTPS
inspection (decryption) for:

- `https://t01.tunnel.kargo.zone/`
- `https://sdn.kargo.zone/`
- `edp12.devicecloud.com:3199`

## Requirements

- Python 3.7+ (standard library only, no extra packages)
- The system CA store, which the Let's Encrypt check uses. On macOS with a
  python.org build, run `Install Certificates.command` once.

## Checks

Each check prints `[step]` log lines and then a final `RESULT: ...` line. Every
check accepts `--timeout` and `--retries`.

### `dns`: DNS resolution

Checks that `sdn.kargo.zone` resolves to exactly `13.56.25.183`.

```bash
python3 kargo_netcheck.py dns                   # use the system resolver (what the device uses)
python3 kargo_netcheck.py dns --server 8.8.8.8  # query 8.8.8.8 directly over UDP 53
```

### `tcp`: outbound TCP ports

Opens a TCP connection to each required port: `54.153.23.224:8022`,
`edp12.devicecloud.com:3199`, `sdn.kargo.zone:443` and `sdn.kargo.zone:80`.

```bash
python3 kargo_netcheck.py tcp
python3 kargo_netcheck.py tcp host:port [host:port ...]   # check custom targets instead
```

### `stun`: STUN over UDP 3478

Sends a Tailscale-style STUN binding request to `sdn.kargo.zone:3478` and checks
that the response is valid. On success it also prints the public (reflexive)
IP:port that the server saw.

| Flag             | Default          | Description                                                         |
| ---------------- | ---------------- | ------------------------------------------------------------------- |
| `--host`         | `sdn.kargo.zone` | STUN server host                                                    |
| `--port`         | `3478`           | STUN server UDP port                                                |
| `--request-type` | `tailscale`      | `tailscale` (type `0x0001`) or `standard` (RFC 5389, type `0x0003`) |

The check is partial (exit code `2`) when a UDP response arrives but it is not
a valid STUN success response.

### `tls`: no TLS inspection

- `t01.tunnel.kargo.zone:443` and `sdn.kargo.zone:443` must present a
  certificate that chains to a public root, matches the hostname and is
  issued by **Let's Encrypt**. If it does not, the check prints the
  certificate that was actually presented, which is usually the firewall's
  inspection CA.
- `edp12.devicecloud.com:3199` is not an HTTPS server, but it does a TLS
  handshake with a private Digi certificate that public CA stores can't
  verify. The check passes only if the certificate subject is exactly
  `C=US; O=Digi International, Inc.; CN=Digi International Server CA`.
