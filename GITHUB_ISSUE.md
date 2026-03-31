<!--
  直接复制以下内容到 GitHub Issue:
  https://github.com/inverse-inc/packetfence/issues/new

  Title: Security: MAB Device Spoofing via Calling-Station-Id Tampering in RADIUS Access-Request
-->

## Summary

PacketFence identifies devices in MAB (MAC Authentication Bypass) authentication by reading `Calling-Station-Id` directly from the RADIUS `Access-Request` packet (`lib/pf/Switch.pm`, `parseRequest()` line ~3276). This MAC address becomes the device identity used for node lookup, VLAN/role assignment, and locationlog tracking.

RFC 2865 provides **no integrity protection** for `Access-Request` attributes. An on-path (MITM) attacker can replace `Calling-Station-Id` (along with `User-Name` and `User-Password`) with an authorized device's MAC address, causing PacketFence to authenticate the unauthorized device as the authorized one.

The NAS validates the Response Authenticator successfully — the attack is **undetectable** at the RADIUS protocol level.

## Affected Code

**`lib/pf/Switch.pm` — `parseRequest()`:**

```perl
sub parseRequest {
    my ( $self, $radius_request ) = @_;
    my $client_mac = ref($radius_request->{'Calling-Station-Id'}) eq 'ARRAY'
        ? clean_mac($radius_request->{'Calling-Station-Id'}[0])
        : clean_mac($radius_request->{'Calling-Station-Id'});
    my $user_name = $self->parseRequestUsername($radius_request);
    my $nas_port_type = ...;
    return ($nas_port_type, $eap_type, $client_mac, $port, $user_name, ...);
}
```

**`lib/pf/radius.pm` — `authorize()`:**

```perl
# Line ~140 — MAC extracted from Calling-Station-Id
my ($nas_port_type, $eap_type, $mac, $port, ...) = $switch->parseRequest($radius_request);

# $mac is then used for:
# - pf::dal::node->find_or_create({"mac" => $mac})  — node lookup
# - locationlog_synchronize(... $mac ...)             — location tracking
# - VLAN/role assignment based on device profile
```

No validation is performed to verify that `Calling-Station-Id` matches the actual connecting device.

## Attack Scenario

```
1. Unauthorized device connects to switch port (MAB enabled)
2. Switch sends Access-Request:
   - Calling-Station-Id = de:ad:be:ef:12:34 (unauthorized)
   - User-Name = deadbeef1234
   - User-Password = deadbeef1234 (encrypted)
3. On-path attacker intercepts and replaces:
   - Calling-Station-Id → aa:bb:cc:dd:ee:ff (authorized printer)
   - User-Name → aabbccddeeff
   - User-Password → re-encoded for aabbccddeeff
4. PacketFence: parseRequest() → $mac = "aabbccddeeff"
5. Node lookup succeeds → Access-Accept with VLAN 10 (corporate)
6. Response Authenticator valid ✓
7. NAS applies corporate VLAN to unauthorized device
```

## Impact

- **Device impersonation** — unauthorized device gains authorized device's network access
- **Network segmentation bypass** — attacker placed on corporate VLAN instead of being rejected
- MAB is widely deployed for printers, IoT devices, cameras, medical equipment
- Same attack model as **CVE-2024-3596 (Blast-RADIUS, CVSS 9.0)**

| | CVE-2024-3596 (Blast-RADIUS) | This issue |
|---|---|---|
| Attack model | On-path MITM | On-path MITM (same) |
| MD5 collision | Yes | **No** |
| Shared secret needed | No | Yes (for User-Password) |
| Complexity | High | **Medium** |
| Impact | Forge Access-Accept/Reject | Device impersonation |

> Note: MAB requires the shared secret for `User-Password` re-encoding. However, in MAB deployments the shared secret is often weak or default, and the attacker only needs to know an authorized MAC address (obtainable via passive network sniffing).

## Proof of Concept

Full end-to-end PoC with Docker environment:

👉 **https://github.com/APEvul-cyber/packetfence-mab-spoofing**

```
STEP 1: Unauthorized device (no MITM) → Access-Reject ✓
STEP 2: Authorized printer (no MITM) → Access-Accept, VLAN 10 ✓
STEP 3: Unauthorized device via MITM → Access-Accept, VLAN 10 ✓

✓ ATTACK SUCCESSFUL — MAB DEVICE SPOOFING CONFIRMED
```

### Reproduce

```bash
git clone https://github.com/APEvul-cyber/packetfence-mab-spoofing.git
cd packetfence-mab-spoofing
docker compose up -d --build
sleep 5
docker compose exec attacker python /scripts/poc_mab_spoofing.py
```

## Suggested Fix

1. **Require `Message-Authenticator`** (RFC 2869) on all `Access-Request` packets to prevent attribute tampering.
2. **Cross-validate MAC** against switch port security tables or SNMP data when available.
3. **Recommend 802.1X** for sensitive VLANs — MAB should only be used for low-risk devices.
4. **Document the risk** — MAB deployments using RADIUS/UDP without RadSec are vulnerable to device impersonation via on-path attackers.

## References

- [CVE-2024-3596 — Blast-RADIUS](https://www.blastradius.fail/)
- [RFC 2865 — RADIUS](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 6614 — RadSec](https://datatracker.ietf.org/doc/html/rfc6614)
- [Full technical report](https://github.com/APEvul-cyber/packetfence-mab-spoofing/blob/main/README.md)
