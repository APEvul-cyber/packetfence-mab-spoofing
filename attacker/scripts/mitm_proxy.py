#!/usr/bin/env python3
"""
通用 RADIUS MITM 代理
======================
拦截 NAS→Server 的 Access-Request，按规则篡改属性后转发。
服务器响应原样转回 NAS（不做任何修改）。

用法：
  作为独立进程运行，监听 UDP 端口，接收 NAS 请求，篡改后转发到真实服务器。
  也可以被 e2e 框架以线程方式启动。
"""
import socket
import struct
import threading
import time
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from radius_utils import *


class MITMProxy:
    """通用 RADIUS MITM 代理"""

    def __init__(self, listen_port=1814, server_addr="172.20.0.10", server_port=1812):
        self.listen_port = listen_port
        self.server_addr = server_addr
        self.server_port = server_port
        self.rules = []       # 篡改规则列表
        self.running = False
        self.sock = None
        self.log = []         # 操作日志

    def add_rule(self, rule):
        """
        添加篡改规则。rule 是一个 dict:
        {
            "action": "replace" | "add" | "remove" | "inject_proxy_state",
            "attr_type": int,          # 目标属性类型
            "new_value": bytes,        # 新值（replace/add 时）
            "description": str,        # 描述
        }
        """
        self.rules.append(rule)

    def clear_rules(self):
        self.rules = []
        self.log = []

    def _parse_attributes(self, data, offset, length):
        """解析属性列表，返回 [(type, raw_bytes), ...]"""
        attrs = []
        pos = offset
        while pos < length:
            if pos + 2 > len(data):
                break
            atype = data[pos]
            alen = data[pos + 1]
            if alen < 2 or pos + alen > len(data):
                break
            attrs.append((atype, data[pos:pos + alen]))
            pos += alen
        return attrs

    def _rebuild_packet(self, code, identifier, authenticator, attr_list):
        """从属性列表重建 RADIUS 数据包"""
        attrs_bytes = b"".join(raw for _, raw in attr_list)
        length = 20 + len(attrs_bytes)
        header = struct.pack("!BBH", code, identifier, length) + authenticator
        return header + attrs_bytes

    def _apply_rules(self, packet):
        """对 Access-Request 应用篡改规则"""
        if len(packet) < 20:
            return packet, []

        code = packet[0]
        identifier = packet[1]
        length = struct.unpack("!H", packet[2:4])[0]
        authenticator = packet[4:20]

        attr_list = self._parse_attributes(packet, 20, length)
        actions_taken = []

        for rule in self.rules:
            action = rule["action"]
            desc = rule.get("description", "")

            if action == "replace":
                target_type = rule["attr_type"]
                new_value = rule["new_value"]
                new_attr = struct.pack("!BB", target_type, 2 + len(new_value)) + new_value
                replaced = False
                for i, (atype, raw) in enumerate(attr_list):
                    if atype == target_type:
                        attr_list[i] = (target_type, new_attr)
                        replaced = True
                        actions_taken.append(f"REPLACE attr {target_type}: {desc}")
                        break
                if not replaced:
                    # 如果不存在则添加
                    attr_list.append((target_type, new_attr))
                    actions_taken.append(f"ADD attr {target_type} (not found, added): {desc}")

            elif action == "add":
                target_type = rule["attr_type"]
                new_value = rule["new_value"]
                new_attr = struct.pack("!BB", target_type, 2 + len(new_value)) + new_value
                attr_list.append((target_type, new_attr))
                actions_taken.append(f"ADD attr {target_type}: {desc}")

            elif action == "remove":
                target_type = rule["attr_type"]
                before = len(attr_list)
                attr_list = [(t, r) for t, r in attr_list if t != target_type]
                if len(attr_list) < before:
                    actions_taken.append(f"REMOVE attr {target_type}: {desc}")

            elif action == "inject_proxy_state":
                ps_data = rule.get("new_value", os.urandom(100))
                ps_attr = struct.pack("!BB", ATTR_PROXY_STATE, 2 + len(ps_data)) + ps_data
                attr_list.append((ATTR_PROXY_STATE, ps_attr))
                actions_taken.append(f"INJECT Proxy-State: {desc}")

        modified = self._rebuild_packet(code, identifier, authenticator, attr_list)
        return modified, actions_taken

    def handle_one(self, data, client_addr, sock):
        """处理单个请求"""
        code = data[0] if data else 0
        identifier = data[1] if len(data) > 1 else 0

        # 应用篡改规则
        modified, actions = self._apply_rules(data)

        log_entry = {
            "client": client_addr,
            "original_size": len(data),
            "modified_size": len(modified),
            "actions": actions,
        }

        # 转发到真实服务器
        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd.settimeout(5.0)
        try:
            fwd.sendto(modified, (self.server_addr, self.server_port))
            resp, _ = fwd.recvfrom(4096)
            # 响应原样转回 NAS（不做任何修改）
            sock.sendto(resp, client_addr)
            log_entry["response_code"] = resp[0] if resp else -1
            log_entry["response_size"] = len(resp)
        except socket.timeout:
            log_entry["response_code"] = -1
            log_entry["error"] = "server timeout"
        except Exception as e:
            log_entry["error"] = str(e)
        finally:
            fwd.close()

        self.log.append(log_entry)

    def start(self):
        """启动代理（阻塞）"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.listen_port))
        self.sock.settimeout(1.0)
        self.running = True

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.handle_one(data, addr, self.sock)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass  # ignore errors during shutdown

        self.sock.close()

    def start_background(self):
        """后台线程启动"""
        t = threading.Thread(target=self.start, daemon=True)
        t.start()
        time.sleep(0.3)  # 等待绑定
        return t

    def stop(self):
        self.running = False
