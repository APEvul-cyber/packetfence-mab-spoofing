"""
RADIUS PoC 公共工具模块
提供 RADIUS 数据包构造和解析的基础功能
"""
import hashlib
import struct
import socket
import os

# RADIUS 常量
RADIUS_AUTH_PORT = 1812
RADIUS_ACCT_PORT = 1813
SHARED_SECRET = b"testing123"
RADIUS_SERVER = "172.20.0.10"

# RADIUS Code
CODE_ACCESS_REQUEST = 1
CODE_ACCESS_ACCEPT = 2
CODE_ACCESS_REJECT = 3
CODE_ACCOUNTING_REQUEST = 4
CODE_ACCOUNTING_RESPONSE = 5

CODE_NAMES = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    11: "Access-Challenge",
}

# RADIUS Attribute Types
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
ATTR_REPLY_MESSAGE = 18
ATTR_VENDOR_SPECIFIC = 26
ATTR_CALLING_STATION_ID = 31
ATTR_PROXY_STATE = 33
ATTR_NAS_PORT_TYPE = 61
ATTR_TUNNEL_TYPE = 64
ATTR_TUNNEL_MEDIUM_TYPE = 65
ATTR_TUNNEL_PRIVATE_GROUP_ID = 81
ATTR_TUNNEL_PASSWORD = 69

ATTR_NAMES = {
    1: "User-Name", 2: "User-Password", 4: "NAS-IP-Address",
    5: "NAS-Port", 6: "Service-Type", 18: "Reply-Message",
    26: "Vendor-Specific", 31: "Calling-Station-Id", 33: "Proxy-State",
    61: "NAS-Port-Type", 64: "Tunnel-Type", 65: "Tunnel-Medium-Type",
    69: "Tunnel-Password", 81: "Tunnel-Private-Group-Id",
}


def encode_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    """RFC 2865 Section 5.2 - User-Password 加密"""
    # 填充到 16 字节的倍数
    padded = password + b'\x00' * (16 - len(password) % 16) if len(password) % 16 != 0 else password
    if len(padded) == 0:
        padded = b'\x00' * 16

    result = b''
    last_block = authenticator
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        digest = hashlib.md5(secret + last_block).digest()
        cipher = bytes(a ^ b for a, b in zip(block, digest))
        result += cipher
        last_block = cipher
    return result


def build_attribute(attr_type: int, value: bytes) -> bytes:
    """构造 RADIUS 属性 TLV"""
    length = 2 + len(value)
    return struct.pack("!BB", attr_type, length) + value


def build_string_attr(attr_type: int, value: str) -> bytes:
    return build_attribute(attr_type, value.encode())


def build_integer_attr(attr_type: int, value: int) -> bytes:
    return build_attribute(attr_type, struct.pack("!I", value))


def build_ipaddr_attr(attr_type: int, ip: str) -> bytes:
    return build_attribute(attr_type, socket.inet_aton(ip))


def build_radius_packet(code: int, identifier: int, authenticator: bytes,
                         attributes: bytes) -> bytes:
    """构造完整的 RADIUS 数据包"""
    length = 20 + len(attributes)
    header = struct.pack("!BBH", code, identifier, length) + authenticator
    return header + attributes


def compute_request_authenticator() -> bytes:
    """生成随机 Request Authenticator"""
    return os.urandom(16)


def compute_response_authenticator(code: int, identifier: int, length: int,
                                    request_auth: bytes, attributes: bytes,
                                    secret: bytes) -> bytes:
    """计算 Response Authenticator: MD5(Code+ID+Length+RequestAuth+Attributes+Secret)"""
    data = struct.pack("!BBH", code, identifier, length) + request_auth + attributes + secret
    return hashlib.md5(data).digest()


def send_radius_packet(packet: bytes, server: str = RADIUS_SERVER,
                        port: int = RADIUS_AUTH_PORT, timeout: float = 5.0) -> bytes:
    """发送 RADIUS 数据包并接收响应"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, addr = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def parse_radius_response(data: bytes) -> dict:
    """解析 RADIUS 响应数据包"""
    if len(data) < 20:
        return {"error": "Packet too short"}

    code, identifier, length = struct.unpack("!BBH", data[:4])
    authenticator = data[4:20]

    result = {
        "code": code,
        "code_name": CODE_NAMES.get(code, f"Unknown({code})"),
        "identifier": identifier,
        "length": length,
        "authenticator": authenticator.hex(),
        "attributes": []
    }

    # 解析属性
    pos = 20
    while pos < length:
        if pos + 2 > len(data):
            break
        attr_type = data[pos]
        attr_len = data[pos + 1]
        if attr_len < 2 or pos + attr_len > len(data):
            break
        attr_value = data[pos + 2:pos + attr_len]

        attr = {
            "type": attr_type,
            "type_name": ATTR_NAMES.get(attr_type, f"Unknown({attr_type})"),
            "length": attr_len,
            "raw_value": attr_value.hex(),
        }

        # 尝试解码常见类型
        if attr_type in (ATTR_USER_NAME, ATTR_REPLY_MESSAGE, ATTR_CALLING_STATION_ID,
                         ATTR_TUNNEL_PRIVATE_GROUP_ID):
            try:
                attr["value"] = attr_value.decode("utf-8")
            except:
                pass
        elif attr_type in (ATTR_NAS_PORT, ATTR_SERVICE_TYPE, ATTR_NAS_PORT_TYPE):
            if len(attr_value) == 4:
                attr["value"] = struct.unpack("!I", attr_value)[0]
        elif attr_type == ATTR_NAS_IP_ADDRESS:
            if len(attr_value) == 4:
                attr["value"] = socket.inet_ntoa(attr_value)
        elif attr_type in (ATTR_TUNNEL_TYPE, ATTR_TUNNEL_MEDIUM_TYPE):
            if len(attr_value) >= 4:
                tag = attr_value[0]
                val = struct.unpack("!I", b'\x00' + attr_value[1:4])[0]
                attr["tag"] = tag
                attr["value"] = val

        result["attributes"].append(attr)
        pos += attr_len

    return result


def print_result(title: str, response: dict):
    """格式化打印结果"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")
    print(f"  Code: {response['code']} ({response['code_name']})")
    print(f"  Identifier: {response['identifier']}")
    print(f"  Length: {response['length']}")
    print(f"  Authenticator: {response['authenticator']}")
    print(f"  Attributes:")
    for attr in response["attributes"]:
        val = attr.get("value", attr["raw_value"])
        print(f"    - {attr['type_name']} (type={attr['type']}): {val}")
    print(f"{'='*60}\n")
