#!/usr/bin/env python3

'''
Natter - https://github.com/MikeWang000000/Natter
Copyright (C) 2023  MikeWang000000

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os
import re
import sys
import json
import time
import errno
import atexit
import codecs
import random
import signal
import socket
import struct
import argparse
import threading
import subprocess

__version__ = "2.1.1"


class Logger(object):
    DEBUG = 0
    INFO  = 1
    WARN  = 2
    ERROR = 3
    rep = {DEBUG: "D", INFO: "I", WARN: "W", ERROR: "E"}
    level = INFO
    if "256color" in os.environ.get("TERM", ""):
        GREY = "\033[90;20m"
        YELLOW_BOLD = "\033[33;1m"
        RED_BOLD = "\033[31;1m"
        RESET = "\033[0m"
    else:
        GREY = YELLOW_BOLD = RED_BOLD = RESET = ""

    @staticmethod
    def set_level(level):
        Logger.level = level

    @staticmethod
    def debug(text=""):
        if Logger.level <= Logger.DEBUG:
            sys.stderr.write((Logger.GREY + "%s [%s] %s\n" + Logger.RESET) % (
                time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.DEBUG], text
            ))

    @staticmethod
    def info(text=""):
        if Logger.level <= Logger.INFO:
            sys.stderr.write(("%s [%s] %s\n") % (
                time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.INFO], text
            ))

    @staticmethod
    def warning(text=""):
        if Logger.level <= Logger.WARN:
            sys.stderr.write((Logger.YELLOW_BOLD + "%s [%s] %s\n" + Logger.RESET) % (
                time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.WARN], text
            ))

    @staticmethod
    def error(text=""):
        if Logger.level <= Logger.ERROR:
            sys.stderr.write((Logger.RED_BOLD + "%s [%s] %s\n" + Logger.RESET) % (
                time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.ERROR], text
            ))


class NatterExit(object):
    atexit.register(lambda : NatterExit._atexit[0]())
    _atexit = [lambda : None]

    @staticmethod
    def set_atexit(func):
        NatterExit._atexit[0] = func


class PortTest(object):
    def test_lan(self, addr, source_ip=None, interface=None, info=False):
        print_status = Logger.info if info else Logger.debug
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socket_set_opt(
                sock,
                bind_addr   = (source_ip, 0) if source_ip else None,
                interface   = interface,
                timeout     = 1
            )
            if sock.connect_ex(addr) == 0:
                print_status("LAN > %-21s [ OPEN ]" % addr_to_str(addr))
                return 1
            else:
                print_status("LAN > %-21s [ CLOSED ]" % addr_to_str(addr))
                return -1
        except (OSError, socket.error) as ex:
            print_status("LAN > %-21s [ UNKNOWN ]" % addr_to_str(addr))
            Logger.debug("Cannot test port %s from LAN because: %s" % (addr_to_str(addr), ex))
            return 0
        finally:
            sock.close()

    def test_wan(self, addr, source_ip=None, interface=None, info=False):
        # only port number in addr is used, WAN IP will be ignored
        print_status = Logger.info if info else Logger.debug
        ret01 = self._test_ifconfigco(addr[1], source_ip, interface)
        if ret01 == 1:
            print_status("WAN > %-21s [ OPEN ]" % addr_to_str(addr))
            return 1
        ret02 = self._test_transmission(addr[1], source_ip, interface)
        if ret02 == 1:
            print_status("WAN > %-21s [ OPEN ]" % addr_to_str(addr))
            return 1
        if ret01 == ret02 == -1:
            print_status("WAN > %-21s [ CLOSED ]" % addr_to_str(addr))
            return -1
        print_status("WAN > %-21s [ UNKNOWN ]" % addr_to_str(addr))
        return 0

    def _test_ifconfigco(self, port, source_ip=None, interface=None):
        # repo: https://github.com/mpolden/echoip
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socket_set_opt(
                sock,
                bind_addr   = (source_ip, 0) if source_ip else None,
                interface   = interface,
                timeout     = 8
            )
            sock.connect(("ifconfig.co", 80))
            sock.sendall((
                "GET /port/%d HTTP/1.0\r\n"
                "Host: ifconfig.co\r\n"
                "User-Agent: curl/8.0.0 (Natter)\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n" % port
            ).encode())
            response = b""
            while True:
                buff = sock.recv(4096)
                if not buff:
                    break
                response += buff
            Logger.debug("port-test: ifconfig.co: %s" % response)
            _, content = response.split(b"\r\n\r\n", 1)
            dat = json.loads(content.decode())
            return 1 if dat["reachable"] else -1
        except (OSError, LookupError, ValueError, TypeError, socket.error) as ex:
            Logger.debug("Cannot test port %d from ifconfig.co because: %s" % (port, ex))
            return 0
        finally:
            sock.close()

    def _test_transmission(self, port, source_ip=None, interface=None):
        # repo: https://github.com/transmission/portcheck
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socket_set_opt(
                sock,
                bind_addr   = (source_ip, 0) if source_ip else None,
                interface   = interface,
                timeout     = 8
            )
            sock.connect(("portcheck.transmissionbt.com", 80))
            sock.sendall((
                "GET /%d HTTP/1.0\r\n"
                "Host: portcheck.transmissionbt.com\r\n"
                "User-Agent: curl/8.0.0 (Natter)\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n" % port
            ).encode())
            response = b""
            while True:
                buff = sock.recv(4096)
                if not buff:
                    break
                response += buff
            Logger.debug("port-test: portcheck.transmissionbt.com: %s" % response)
            _, content = response.split(b"\r\n\r\n", 1)
            if content.strip() == b"1":
                return 1
            elif content.strip() == b"0":
                return -1
            raise ValueError("Unexpected response: %s" % response)
        except (OSError, LookupError, ValueError, TypeError, socket.error) as ex:
            Logger.debug(
                "Cannot test port %d from portcheck.transmissionbt.com "
                "because: %s" % (port, ex)
            )
            return 0
        finally:
            sock.close()


class StunClient(object):
    class ServerUnavailable(Exception):
        pass

    def __init__(self, stun_server_list, source_host="0.0.0.0", source_port=0,
                 interface=None, udp=False):
        if not stun_server_list:
            raise ValueError("STUN server list is empty")
        self.stun_server_list = stun_server_list
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp

    def get_mapping(self):
        first = self.stun_server_list[0]
        while True:
            try:
                return self._get_mapping()
            except StunClient.ServerUnavailable as ex:
                Logger.warning("stun: STUN server %s is unavailable: %s" % (
                    addr_to_uri(self.stun_server_list[0], udp = self.udp), ex
                ))
                self.stun_server_list.append(self.stun_server_list.pop(0))
                if self.stun_server_list[0] == first:
                    Logger.error("stun: No STUN server is available right now")
                    # force sleep for 10 seconds, then try the next loop
                    time.sleep(10)

    def _get_mapping(self):
        # ref: https://www.rfc-editor.org/rfc/rfc5389
        socket_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        stun_host, stun_port = self.stun_server_list[0]
        sock = socket.socket(socket.AF_INET, socket_type)
        socket_set_opt(
            sock,
            reuse       = True,
            bind_addr   = (self.source_host, self.source_port),
            interface   = self.interface,
            timeout     = 3
        )
        try:
            sock.connect((stun_host, stun_port))
            inner_addr = sock.getsockname()
            self.source_host, self.source_port = inner_addr
            sock.send(struct.pack(
                "!LLLLL", 0x00010000, 0x2112a442, 0x4e415452,
                random.getrandbits(32), random.getrandbits(32)
            ))
            buff = sock.recv(1500)
            ip = port = 0
            payload = buff[20:]
            while payload:
                attr_type, attr_len = struct.unpack("!HH", payload[:4])
                if attr_type in [1, 32]:
                    _, _, port, ip = struct.unpack("!BBHL", payload[4:4+attr_len])
                    if attr_type == 32:
                        port ^= 0x2112
                        ip ^= 0x2112a442
                    break
                payload = payload[4 + attr_len:]
            else:
                raise ValueError("Invalid STUN response")
            outer_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!L", ip)), port
            Logger.debug("stun: Got address %s from %s, source %s" % (
                addr_to_uri(outer_addr, udp=self.udp),
                addr_to_uri((stun_host, stun_port), udp=self.udp),
                addr_to_uri(inner_addr, udp=self.udp)
            ))
            return inner_addr, outer_addr
        except (OSError, ValueError, struct.error, socket.error) as ex:
            raise StunClient.ServerUnavailable(ex)
        finally:
            sock.close()


class KeepAlive(object):
    def __init__(self, host, port, source_host, source_port, interface=None, udp=False):
        self.sock = None
        self.host = host
        self.port = port
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp
        self.reconn = False

    def __del__(self):
        if self.sock:
            self.sock.close()

    def _connect(self):
        sock_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)
        socket_set_opt(
            sock,
            reuse       = True,
            bind_addr   = (self.source_host, self.source_port),
            interface   = self.interface,
            timeout     = 3
        )
        sock.connect((self.host, self.port))
        if not self.udp:
            Logger.debug("keep-alive: Connected to host %s" % (
                addr_to_uri((self.host, self.port), udp=self.udp)
            ))
            if self.reconn:
                Logger.info("keep-alive: connection restored")
        self.reconn = False
        self.sock = sock

    def keep_alive(self):
        if self.sock is None:
            self._connect()
        if self.udp:
            self._keep_alive_udp()
        else:
            self._keep_alive_tcp()
        Logger.debug("keep-alive: OK")

    def reset(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.reconn = True

    def _keep_alive_tcp(self):
        # send a HTTP request
        self.sock.sendall((
            "HEAD /natter-keep-alive HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/8.0.0 (Natter)\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n"
            "\r\n" % self.host
        ).encode())
        buff = b""
        try:
            while True:
                buff = self.sock.recv(4096)
                if not buff:
                    raise OSError("Keep-alive server closed connection")
        except socket.timeout as ex:
            if not buff:
                raise ex
            return

    def _keep_alive_udp(self):
        # send a DNS request
        self.sock.send(
            struct.pack(
                "!HHHHHH", random.getrandbits(16), 0x0100, 0x0001, 0x0000, 0x0000, 0x0000
            ) + b"\x09keepalive\x06natter\x00" + struct.pack("!HH", 0x0001, 0x0001)
        )
        buff = b""
        try:
            while True:
                buff = self.sock.recv(1500)
                if not buff:
                    raise OSError("Keep-alive server closed connection")
        except socket.timeout as ex:
            if not buff:
                raise ex
            # fix: Keep-alive cause STUN socket timeout on Windows
            if sys.platform == "win32":
                self.reset()
            return


class ForwardNone(object):
    # Do nothing. Don't forward.
    def start_forward(self, ip, port, toip, toport, udp=False):
        pass

    def stop_forward(self):
        pass


class ForwardTestServer(object):
    def __init__(self):
        self.active = False
        self.sock = None
        self.sock_type = None
        self.buff_size = 8192
        self.timeout = 3

    # Start a socket server for testing purpose
    # target address is ignored
    def start_forward(self, ip, port, toip, toport, udp=False):
        self.sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, self.sock_type)
        socket_set_opt(
            self.sock,
            reuse       = True,
            bind_addr   = ("", port)
        )
        Logger.debug("fwd-test: Starting test server at %s" % addr_to_uri((ip, port), udp=udp))
        if udp:
            th = start_daemon_thread(self._test_server_run_udp)
        else:
            th = start_daemon_thread(self._test_server_run_http)
        time.sleep(1)
        if not th.is_alive():
            raise OSError("Test server thread exited too quickly")
        self.active = True

    def _test_server_run_http(self):
        self.sock.listen(5)
        while self.sock.fileno() != -1:
            try:
                conn, addr = self.sock.accept()
                Logger.debug("fwd-test: got client %s" % (addr,))
            except (OSError, socket.error):
                return
            try:
                conn.settimeout(self.timeout)
                conn.recv(self.buff_size)
                content = "<html><body><h1>It works!</h1><hr/>Natter</body></html>"
                content_len = len(content.encode())
                data = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n"
                    "Server: Natter\r\n"
                    "\r\n"
                    "%s\r\n" % (content_len, content)
                ).encode()
                conn.sendall(data)
                conn.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass
            finally:
                conn.close()

    def _test_server_run_udp(self):
        while self.sock.fileno() != -1:
            try:
                msg, addr = self.sock.recvfrom(self.buff_size)
                Logger.debug("fwd-test: got client %s" % (addr,))
                self.sock.sendto(b"It works! - Natter\r\n", addr)
            except (OSError, socket.error):
                return

    def stop_forward(self):
        Logger.debug("fwd-test: Stopping test server")
        self.sock.close()
        self.active = False


class ForwardIptables(object):
    def __init__(self, snat=False, sudo=False):
        self.rules = []
        self.active = False
        self.min_ver = (1, 4, 1)
        self.curr_ver = (0, 0, 0)
        self.snat = snat
        self.sudo = sudo
        if sudo:
            self.iptables_cmd = ["sudo", "-n", "iptables"]
        else:
            self.iptables_cmd = ["iptables"]
        if not self._iptables_check():
            raise OSError("iptables >= %s not available" % str(self.min_ver))
        # wait for iptables lock, since iptables 1.4.20
        if self.curr_ver >= (1, 4, 20):
            self.iptables_cmd += ["-w"]
        self._iptables_init()
        self._iptables_clean()

    def __del__(self):
        if self.active:
            self.stop_forward()

    def _iptables_check(self):
        if os.name != "posix":
            return False
        if not self.sudo and os.getuid() != 0:
            Logger.warning("fwd-iptables: You are not root")
        try:
            output = subprocess.check_output(
                self.iptables_cmd + ["--version"]
            ).decode()
        except (OSError, subprocess.CalledProcessError) as e:
            return False
        m = re.search(r"iptables v([0-9]+)\.([0-9]+)\.([0-9]+)", output)
        if m:
            self.curr_ver = tuple(int(v) for v in m.groups())
            Logger.debug("fwd-iptables: Found iptables %s" % str(self.curr_ver))
            if self.curr_ver < self.min_ver:
                return False
        # check nat table
        try:
            subprocess.check_output(
                self.iptables_cmd + ["-t", "nat", "--list-rules"]
            )
        except (OSError, subprocess.CalledProcessError) as e:
            return False
        return True

    def _iptables_init(self):
        try:
            subprocess.check_output(
                self.iptables_cmd + ["-t", "nat", "--list-rules", "NATTER"],
                stderr=subprocess.STDOUT
            )
            return
        except subprocess.CalledProcessError:
            pass
        Logger.debug("fwd-iptables: Creating Natter chain")
        subprocess.check_output(
            self.iptables_cmd + ["-t", "nat", "-N", "NATTER"]
        )
        subprocess.check_output(
            self.iptables_cmd + ["-t", "nat", "-I", "PREROUTING", "-j", "NATTER"]
        )
        subprocess.check_output(
            self.iptables_cmd + ["-t", "nat", "-I", "OUTPUT", "-j", "NATTER"]
        )
        subprocess.check_output(
            self.iptables_cmd + ["-t", "nat", "-N", "NATTER_SNAT"]
        )
        subprocess.check_output(
            self.iptables_cmd + ["-t", "nat", "-I", "POSTROUTING", "-j", "NATTER_SNAT"]
        )
        subprocess.check_output(
            self.iptables_cmd + ["-t", "nat", "-I", "INPUT", "-j", "NATTER_SNAT"]
        )

    def _iptables_clean(self):
        Logger.debug("fwd-iptables: Cleaning up Natter rules")
        while self.rules:
            rule = self.rules.pop()
            rule_rm = ["-D" if arg in ("-I", "-A") else arg for arg in rule]
            try:
                subprocess.check_output(
                    self.iptables_cmd + rule_rm,
                    stderr=subprocess.STDOUT
                )
                return
            except subprocess.CalledProcessError as ex:
                Logger.error("fwd-iptables: Failed to execute %s: %s" % (ex.cmd, ex.output))
                continue

    def start_forward(self, ip, port, toip, toport, udp=False):
        if ip != toip:
            self._check_sys_forward_config()
        if (ip, port) == (toip, toport):
            raise ValueError("Cannot forward to the same address %s" % addr_to_str((ip, port)))
        proto = "udp" if udp else "tcp"
        Logger.debug("fwd-iptables: Adding rule %s forward to %s" % (
            addr_to_uri((ip, port), udp=udp), addr_to_uri((toip, toport), udp=udp)
        ))
        rule = [
            "-t",       "nat",
            "-I",       "NATTER",
            "-p",       proto,
            "--dst",    ip,
            "--dport",  "%d" % port,
            "-j",       "DNAT",
            "--to-destination", "%s:%d" % (toip, toport)
        ]
        subprocess.check_output(self.iptables_cmd + rule)
        self.rules.append(rule)
        if self.snat:
            rule = [
                "-t",       "nat",
                "-I",       "NATTER_SNAT",
                "-p",       proto,
                "--dst",    toip,
                "--dport",  "%d" % toport,
                "-j",       "SNAT",
                "--to-source", ip
            ]
            subprocess.check_output(self.iptables_cmd + rule)
            self.rules.append(rule)
        self.active = True

    def stop_forward(self):
        self._iptables_clean()
        self.active = False

    def _check_sys_forward_config(self):
        fpath = "/proc/sys/net/ipv4/ip_forward"
        if os.path.exists(fpath):
            fin = open(fpath, "r")
            buff = fin.read()
            fin.close()
            if buff.strip() != "1":
                raise OSError("IP forwarding is not allowed. Please do `sysctl net.ipv4.ip_forward=1`")
        else:
            Logger.warning("fwd-iptables: '%s' not found" % str(fpath))


class ForwardSudoIptables(ForwardIptables):
    def __init__(self):
        super().__init__(sudo=True)


class ForwardIptablesSnat(ForwardIptables):
    def __init__(self):
        super().__init__(snat=True)


class ForwardSudoIptablesSnat(ForwardIptables):
    def __init__(self):
        super().__init__(snat=True, sudo=True)


class ForwardNftables(object):
    def __init__(self, snat=False, sudo=False):
        self.handle = -1
        self.handle_snat = -1
        self.active = False
        self.min_ver = (0, 9, 0)
        self.snat = snat
        self.sudo = sudo
        if sudo:
            self.nftables_cmd = ["sudo", "-n", "nft"]
        else:
            self.nftables_cmd = ["nft"]
        if not self._nftables_check():
            raise OSError("nftables >= %s not available" % str(self.min_ver))
        self._nftables_init()
        self._nftables_clean()

    def __del__(self):
        if self.active:
            self.stop_forward()

    def _nftables_check(self):
        if os.name != "posix":
            return False
        if not self.sudo and os.getuid() != 0:
            Logger.warning("fwd-nftables: You are not root")
        try:
            output = subprocess.check_output(
                self.nftables_cmd + ["--version"]
            ).decode()
        except (OSError, subprocess.CalledProcessError) as e:
            return False
        m = re.search(r"nftables v([0-9]+)\.([0-9]+)\.([0-9]+)", output)
        if m:
            curr_ver = tuple(int(v) for v in m.groups())
            Logger.debug("fwd-nftables: Found nftables %s" % str(curr_ver))
            if curr_ver < self.min_ver:
                return False
        # check nat table
        try:
            subprocess.check_output(
                self.nftables_cmd + ["list table ip nat"]
            )
        except (OSError, subprocess.CalledProcessError) as e:
            return False
        return True

    def _nftables_init(self):
        try:
            subprocess.check_output(
                self.nftables_cmd + ["list chain ip nat NATTER"],
                stderr=subprocess.STDOUT
            )
            return
        except subprocess.CalledProcessError:
            pass
        Logger.debug("fwd-nftables: Creating Natter chain")
        subprocess.check_output(
            self.nftables_cmd + ["add chain ip nat NATTER"]
        )
        subprocess.check_output(
            self.nftables_cmd + ["insert rule ip nat PREROUTING counter jump NATTER"]
        )
        subprocess.check_output(
            self.nftables_cmd + ["insert rule ip nat OUTPUT counter jump NATTER"]
        )
        subprocess.check_output(
            self.nftables_cmd + ["add chain ip nat NATTER_SNAT"]
        )
        subprocess.check_output(
            self.nftables_cmd + ["insert rule ip nat PREROUTING counter jump NATTER_SNAT"]
        )
        subprocess.check_output(
            self.nftables_cmd + ["insert rule ip nat OUTPUT counter jump NATTER_SNAT"]
        )

    def _nftables_clean(self):
        Logger.debug("fwd-nftables: Cleaning up Natter rules")
        if self.handle > 0:
            subprocess.check_output(
                self.nftables_cmd + ["delete rule ip nat NATTER handle %d" % self.handle]
            )
        if self.handle_snat > 0:
            subprocess.check_output(
                self.nftables_cmd + ["delete rule ip nat NATTER_SNAT handle %d" % self.handle_snat]
            )

    def start_forward(self, ip, port, toip, toport, udp=False):
        if ip != toip:
            self._check_sys_forward_config()
        if (ip, port) == (toip, toport):
            raise ValueError("Cannot forward to the same address %s" % addr_to_str((ip, port)))
        proto = "udp" if udp else "tcp"
        Logger.debug("fwd-nftables: Adding rule %s forward to %s" % (
            addr_to_uri((ip, port), udp=udp), addr_to_uri((toip, toport), udp=udp)
        ))
        output = subprocess.check_output(self.nftables_cmd + [
            "--echo", "--handle",
            "insert rule ip nat NATTER ip daddr %s %s dport %d counter dnat to %s:%d" % (
                ip, proto, port, toip, toport
            )
        ]).decode()
        m = re.search(r"# handle ([0-9]+)$", output, re.MULTILINE)
        if not m:
            raise ValueError("Unknown nftables handle")
        self.handle = int(m.group(1))
        if self.snat:
            output = subprocess.check_output(self.nftables_cmd + [
                "--echo", "--handle",
                "insert rule ip nat NATTER_SNAT ip daddr %s %s dport %d counter snat to %s" % (
                    toip, proto, toport, ip
                )
            ]).decode()
            m = re.search(r"# handle ([0-9]+)$", output, re.MULTILINE)
            if not m:
                raise ValueError("Unknown nftables handle")
            self.handle_snat = int(m.group(1))
        self.active = True

    def stop_forward(self):
        self._nftables_clean()
        self.active = False

    def _check_sys_forward_config(self):
        fpath = "/proc/sys/net/ipv4/ip_forward"
        if os.path.exists(fpath):
            fin = open(fpath, "r")
            buff = fin.read()
            fin.close()
            if buff.strip() != "1":
                raise OSError("IP forwarding is disabled by system. Please do `sysctl net.ipv4.ip_forward=1`")
        else:
            Logger.warning("fwd-nftables: '%s' not found" % str(fpath))


class ForwardSudoNftables(ForwardNftables):
    def __init__(self):
        super().__init__(sudo=True)


class ForwardNftablesSnat(ForwardNftables):
    def __init__(self):
        super().__init__(snat=True)


class ForwardSudoNftablesSnat(ForwardNftables):
    def __init__(self):
        super().__init__(snat=True, sudo=True)


class ForwardGost(object):
    def __init__(self):
        self.active = False
        self.min_ver = (2, 3)
        self.proc = None
        self.udp_timeout = 60
        if not self._gost_check():
            raise OSError("gost >= %s not available" % str(self.min_ver))

    def __del__(self):
        if self.active:
            self.stop_forward()

    def _gost_check(self):
        try:
            output = subprocess.check_output(
                ["gost", "-V"], stderr=subprocess.STDOUT
            ).decode()
        except (OSError, subprocess.CalledProcessError) as e:
            return False
        m = re.search(r"gost v?([0-9]+)\.([0-9]+)", output)
        if m:
            current_ver = tuple(int(v) for v in m.groups())
            Logger.debug("fwd-gost: Found gost %s" % str(current_ver))
            return current_ver >= self.min_ver
        return False

    def start_forward(self, ip, port, toip, toport, udp=False):
        if (ip, port) == (toip, toport):
            raise ValueError("Cannot forward to the same address %s" % addr_to_str((ip, port)))
        proto = "udp" if udp else "tcp"
        Logger.debug("fwd-gost: Starting gost %s forward to %s" % (
            addr_to_uri((ip, port), udp=udp), addr_to_uri((toip, toport), udp=udp)
        ))
        gost_arg = "-L=%s://:%d/%s:%d" % (proto, port, toip, toport)
        if udp:
            gost_arg += "?ttl=%ds" % self.udp_timeout
        self.proc = subprocess.Popen(["gost", gost_arg])
        time.sleep(1)
        if self.proc.poll() is not None:
            raise OSError("gost exited too quickly")
        self.active = True

    def stop_forward(self):
        Logger.debug("fwd-gost: Stopping gost")
        if self.proc and self.proc.returncode is not None:
            return
        self.proc.terminate()
        self.active = False


class ForwardSocat(object):
    def __init__(self):
        self.active = False
        self.min_ver = (1, 7, 2)
        self.proc = None
        self.udp_timeout = 60
        self.max_children = 128
        if not self._socat_check():
            raise OSError("socat >= %s not available" % str(self.min_ver))

    def __del__(self):
        if self.active:
            self.stop_forward()

    def _socat_check(self):
        try:
            output = subprocess.check_output(
                ["socat", "-V"], stderr=subprocess.STDOUT
            ).decode()
        except (OSError, subprocess.CalledProcessError) as e:
            return False
        m = re.search(r"socat version ([0-9]+)\.([0-9]+)\.([0-9]+)", output)
        if m:
            current_ver = tuple(int(v) for v in m.groups())
            Logger.debug("fwd-socat: Found socat %s" % str(current_ver))
            return current_ver >= self.min_ver
        return False

    def start_forward(self, ip, port, toip, toport, udp=False):
        if (ip, port) == (toip, toport):
            raise ValueError("Cannot forward to the same address %s" % addr_to_str((ip, port)))
        proto = "UDP" if udp else "TCP"
        Logger.debug("fwd-socat: Starting socat %s forward to %s" % (
            addr_to_uri((ip, port), udp=udp), addr_to_uri((toip, toport), udp=udp)
        ))
        if udp:
            socat_cmd = ["socat", "-T%d" % self.udp_timeout]
        else:
            socat_cmd = ["socat"]
        self.proc = subprocess.Popen(socat_cmd + [
            "%s4-LISTEN:%d,reuseaddr,fork,max-children=%d" % (proto, port, self.max_children),
            "%s4:%s:%d" % (proto, toip, toport)
        ])
        time.sleep(1)
        if self.proc.poll() is not None:
            raise OSError("socat exited too quickly")
        self.active = True

    def stop_forward(self):
        Logger.debug("fwd-socat: Stopping socat")
        if self.proc and self.proc.returncode is not None:
            return
        self.proc.terminate()
        self.active = False


class ForwardSocket(object):
    def __init__(self):
        self.active = False
        self.sock = None
        self.sock_type = None
        self.outbound_addr = None
        self.buff_size = 8192
        self.udp_timeout = 60
        self.max_threads = 128

    def __del__(self):
        if self.active:
            self.stop_forward()

    def start_forward(self, ip, port, toip, toport, udp=False):
        if (ip, port) == (toip, toport):
            raise ValueError("Cannot forward to the same address %s" % addr_to_str((ip, port)))
        self.sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, self.sock_type)
        socket_set_opt(
            self.sock,
            reuse       = True,
            bind_addr   = ("", port)
        )
        self.outbound_addr = toip, toport
        Logger.debug("fwd-socket: Starting socket %s forward to %s" % (
            addr_to_uri((ip, port), udp=udp), addr_to_uri((toip, toport), udp=udp)
        ))
        if udp:
            th = start_daemon_thread(self._socket_udp_recvfrom)
        else:
            th = start_daemon_thread(self._socket_tcp_listen)
        time.sleep(1)
        if not th.is_alive():
            raise OSError("Socket thread exited too quickly")
        self.active = True

    def _socket_tcp_listen(self):
        self.sock.listen(5)
        while True:
            try:
                sock_inbound, _ = self.sock.accept()
            except (OSError, socket.error) as ex:
                if not closed_socket_ex(ex):
                    Logger.error("fwd-socket: socket listening thread is exiting: %s" % ex)
                return
            sock_outbound = socket.socket(socket.AF_INET, self.sock_type)
            try:
                sock_outbound.settimeout(3)
                sock_outbound.connect(self.outbound_addr)
                sock_outbound.settimeout(None)
                if threading.active_count() >= self.max_threads:
                    raise OSError("Too many threads")
                start_daemon_thread(self._socket_tcp_forward, args=(sock_inbound, sock_outbound))
                start_daemon_thread(self._socket_tcp_forward, args=(sock_outbound, sock_inbound))
            except (OSError, socket.error) as ex:
                Logger.error("fwd-socket: cannot forward port: %s" % ex)
                sock_inbound.close()
                sock_outbound.close()
                continue

    def _socket_tcp_forward(self, sock_to_recv, sock_to_send):
        try:
            while sock_to_recv.fileno() != -1:
                buff = sock_to_recv.recv(self.buff_size)
                if buff and sock_to_send.fileno() != -1:
                    sock_to_send.sendall(buff)
                else:
                    sock_to_recv.close()
                    sock_to_send.close()
                    return
        except (OSError, socket.error) as ex:
            if not closed_socket_ex(ex):
                Logger.error("fwd-socket: socket forwarding thread is exiting: %s" % ex)
            sock_to_recv.close()
            sock_to_send.close()
            return

    def _socket_udp_recvfrom(self):
        outbound_socks = {}
        while True:
            try:
                buff, addr = self.sock.recvfrom(self.buff_size)
                s = outbound_socks.get(addr)
            except (OSError, socket.error) as ex:
                if not closed_socket_ex(ex):
                    Logger.error("fwd-socket: socket recvfrom thread is exiting: %s" % ex)
                return
            try:
                if not s:
                    s = outbound_socks[addr] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(self.udp_timeout)
                    s.connect(self.outbound_addr)
                    if threading.active_count() >= self.max_threads:
                        raise OSError("Too many threads")
                    start_daemon_thread(self._socket_udp_send, args=(self.sock, s, addr))
                if buff:
                    s.send(buff)
                else:
                    s.close()
                    del outbound_socks[addr]
            except (OSError, socket.error):
                if addr in outbound_socks:
                    outbound_socks[addr].close()
                    del outbound_socks[addr]
                continue

    def _socket_udp_send(self, server_sock, outbound_sock, client_addr):
        try:
            while outbound_sock.fileno() != -1:
                buff = outbound_sock.recv(self.buff_size)
                if buff:
                    server_sock.sendto(buff, client_addr)
                else:
                    outbound_sock.close()
        except (OSError, socket.error) as ex:
            if not closed_socket_ex(ex):
                Logger.error("fwd-socket: socket send thread is exiting: %s" % ex)
            outbound_sock.close()
            return

    def stop_forward(self):
        Logger.debug("fwd-socket: Stopping socket")
        self.sock.close()
        self.active = False


class UPnPService(object):
    def __init__(self, device, bind_ip = None, interface = None):
        self.device             = device
        self.service_type       = None
        self.service_id         = None
        self.scpd_url           = None
        self.control_url        = None
        self.eventsub_url       = None
        self._sock_timeout      = 3
        self._bind_ip           = bind_ip
        self._bind_interface    = interface

    def __repr__(self):
        return "<UPnPService service_type=%s, service_id=%s>" % (
            repr(self.service_type), repr(self.service_id)
        )

    def is_valid(self):
        if self.service_type and self.service_id and self.control_url:
            return True
        return False

    def is_forward(self):
        if self.service_type in (
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANPPPConnection:1"
        ) and self.service_id and self.control_url:
            return True
        return False

    def forward_port(self, host, port, dest_host, dest_port, udp=False, duration=0):
        if not self.is_forward():
            raise NotImplementedError("Unsupported service type: %s" % self.service_type)

        proto = "UDP" if udp else "TCP"
        ctl_hostname, ctl_port, ctl_path = split_url(self.control_url)
        descpt = "Natter"
        content = (
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"\r\n"
            "  s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
            "  <s:Body>\r\n"
            "    <m:AddPortMapping xmlns:m=\"%s\">\r\n"
            "      <NewRemoteHost>%s</NewRemoteHost>\r\n"
            "      <NewExternalPort>%s</NewExternalPort>\r\n"
            "      <NewProtocol>%s</NewProtocol>\r\n"
            "      <NewInternalPort>%s</NewInternalPort>\r\n"
            "      <NewInternalClient>%s</NewInternalClient>\r\n"
            "      <NewEnabled>1</NewEnabled>\r\n"
            "      <NewPortMappingDescription>%s</NewPortMappingDescription>\r\n"
            "      <NewLeaseDuration>%d</NewLeaseDuration>\r\n"
            "    </m:AddPortMapping>\r\n"
            "  </s:Body>\r\n"
            "</s:Envelope>\r\n" % (
                self.service_type, host, port, proto, dest_port, dest_host, descpt, duration
            )
        )
        content_len = len(content.encode())
        data = (
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: curl/8.0.0 (Natter)\r\n"
            "Accept: */*\r\n"
            "SOAPAction: \"%s#AddPortMapping\"\r\n"
            "Content-Type: text/xml\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s\r\n" % (ctl_path, ctl_hostname, ctl_port, self.service_type, content_len, content)
        ).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_set_opt(
            sock,
            bind_addr   = (self._bind_ip, 0) if self._bind_ip else None,
            interface   = self._bind_interface,
            timeout     = self._sock_timeout
        )
        sock.connect((ctl_hostname, ctl_port))
        sock.sendall(data)
        response = b""
        while True:
            buff = sock.recv(4096)
            if not buff:
                break
            response += buff
        sock.close()
        r = response.decode("utf-8", "ignore")
        errno = errmsg = ""
        m = re.search(r"<errorCode\s*>([^<]*?)</errorCode\s*>", r)
        if m:
            errno = m.group(1).strip()
        m = re.search(r"<errorDescription\s*>([^<]*?)</errorDescription\s*>", r)
        if m:
            errmsg = m.group(1).strip()
        if errno or errmsg:
            Logger.error("upnp: Error from service %s of device %s: [%s] %s" % (
                self.service_type, self.device, errno, errmsg
            ))
            return False
        return True


class UPnPDevice(object):
    def __init__(self, ipaddr, xml_urls, bind_ip = None, interface = None):
        self.ipaddr = ipaddr
        self.xml_urls = xml_urls
        self.services = []
        self.forward_srv = None
        self._sock_timeout = 3
        self._bind_ip = bind_ip
        self._bind_interface = interface

    def __repr__(self):
        return "<UPnPDevice ipaddr=%s>" % (
            repr(self.ipaddr),
        )

    def _load_services(self):
        if self.services:
            return
        services_d = {}     # service_id => UPnPService()
        for url in self.xml_urls:
            sd = self._get_srv_dict(url)
            if not sd:
                continue
            services_d.update(sd)
        self.services.extend(services_d.values())
        for srv in self.services:
            if srv.is_forward():
                self.forward_srv = srv
                break

    def _http_get(self, url):
        hostname, port, path = split_url(url)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_set_opt(
            sock,
            bind_addr   = (self._bind_ip, 0) if self._bind_ip else None,
            interface   = self._bind_interface,
            timeout     = self._sock_timeout
        )
        sock.connect((hostname, port))
        data = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/8.0.0 (Natter)\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n" % (path, hostname)
        ).encode()
        sock.sendall(data)
        response = b""
        while True:
            buff = sock.recv(4096)
            if not buff:
                break
            response += buff
        sock.close()
        if not response.startswith(b"HTTP/"):
            raise ValueError("Invalid response from HTTP server")
        s = response.split(b"\r\n\r\n", 1)
        if len(s) != 2:
            raise ValueError("Invalid response from HTTP server")
        return s[1]

    def _get_srv_dict(self, url):
        try:
            xmlcontent = self._http_get(url).decode("utf-8", "ignore")
        except (OSError, socket.error, ValueError) as ex:
            Logger.error("upnp: failed to load service from %s: %s" % (url, ex))
            return
        services_d = {}
        srv_str_l = re.findall(r"<service\s*>([\s\S]+?)</service\s*>", xmlcontent)
        for srv_str in srv_str_l:
            srv = UPnPService(self, bind_ip=self._bind_ip, interface=self._bind_interface)
            m = re.search(r"<serviceType\s*>([^<]*?)</serviceType\s*>", srv_str)
            if m:
                srv.service_type    = m.group(1).strip()
            m = re.search(r"<serviceId\s*>([^<]*?)</serviceId\s*>", srv_str)
            if m:
                srv.service_id      = m.group(1).strip()
            m = re.search(r"<SCPDURL\s*>([^<]*?)</SCPDURL\s*>", srv_str)
            if m:
                srv.scpd_url        = full_url(m.group(1).strip(), url)
            m = re.search(r"<controlURL\s*>([^<]*?)</controlURL\s*>", srv_str)
            if m:
                srv.control_url     = full_url(m.group(1).strip(), url)
            m = re.search(r"<eventSubURL\s*>([^<]*?)</eventSubURL\s*>", srv_str)
            if m:
                srv.eventsub_url    = full_url(m.group(1).strip(), url)
            if srv.is_valid():
                services_d[srv.service_id] = srv
        return services_d


class UPnPClient(object):
    def __init__(self, bind_ip = None, interface = None):
        self.ssdp_addr          = ("239.255.255.250", 1900)
        self.router             = None
        self._sock_timeout      = 1
        self._fwd_host          = None
        self._fwd_port          = None
        self._fwd_dest_host     = None
        self._fwd_dest_port     = None
        self._fwd_udp           = False
        self._fwd_duration      = 0
        self._fwd_started       = False
        self._bind_ip           = bind_ip
        self._bind_interface    = interface

    def discover_router(self):
        router_l = []
        try:
            devs = self._discover()
            for dev in devs:
                if dev.forward_srv:
                    router_l.append(dev)
        except (OSError, socket.error) as ex:
            Logger.error("upnp: failed to discover router: %s" % ex)
        if not router_l:
            self.router = None
        elif len(router_l) > 1:
            Logger.warning("upnp: multiple routers found: %s" % (router_l,))
            self.router = router_l[0]
        else:
            self.router = router_l[0]
        return self.router

    def _discover(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket_set_opt(
            sock,
            reuse       = True,
            bind_addr   = (self._bind_ip, 0) if self._bind_ip else None,
            interface   = self._bind_interface,
            timeout     = self._sock_timeout
        )
        dat01 = (
            "M-SEARCH * HTTP/1.1\r\n"
            "ST: ssdp:all\r\n"
            "MX: 2\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "HOST: %s:%d\r\n"
            "\r\n" % self.ssdp_addr
        ).encode()

        dat02 = (
            "M-SEARCH * HTTP/1.1\r\n"
            "ST: upnp:rootdevice\r\n"
            "MX: 2\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "HOST: %s:%d\r\n"
            "\r\n" % self.ssdp_addr
        ).encode()

        sock.sendto(dat01, self.ssdp_addr)
        sock.sendto(dat02, self.ssdp_addr)

        upnp_urls_d = {}
        while True:
            try:
                buff, addr = sock.recvfrom(4096)
                m = re.search(r"LOCATION: *(http://[^\[]\S+)\s+", buff.decode("utf-8"))
                if not m:
                    continue
                ipaddr = addr[0]
                location = m.group(1)
                Logger.debug("upnp: Got URL %s" % location)
                if ipaddr in upnp_urls_d:
                    upnp_urls_d[ipaddr].add(location)
                else:
                    upnp_urls_d[ipaddr] = set([location])
            except socket.timeout:
                break

        devs = []
        for ipaddr, urls in upnp_urls_d.items():
            d = UPnPDevice(ipaddr, urls, bind_ip=self._bind_ip, interface=self._bind_interface)
            d._load_services()
            devs.append(d)

        return devs

    def forward(self, host, port, dest_host, dest_port, udp=False, duration=0):
        if not self.router:
            raise RuntimeError("No router is available")
        self.router.forward_srv.forward_port(host, port, dest_host, dest_port, udp, duration)
        self._fwd_host      = host
        self._fwd_port      = port
        self._fwd_dest_host = dest_host
        self._fwd_dest_port = dest_port
        self._fwd_udp       = udp
        self._fwd_duration  = duration
        self._fwd_started   = True

    def renew(self):
        if not self._fwd_started:
            raise RuntimeError("UPnP forward not started")
        self.router.forward_srv.forward_port(
            self._fwd_host, self._fwd_port, self._fwd_dest_host,
            self._fwd_dest_port, self._fwd_udp, self._fwd_duration
        )
        Logger.debug("upnp: OK")


class NatterExitException(Exception):
    pass


class NatterRetryException(Exception):
    pass


def socket_set_opt(sock, reuse=False, bind_addr=None, interface=None, timeout=-1):
    if reuse:
        if hasattr(socket, "SO_REUSEADDR"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if interface is not None:
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0"
            )
        else:
            raise RuntimeError("Binding to an interface is not supported on your platform.")
    if bind_addr is not None:
        sock.bind(bind_addr)
    if timeout != -1:
        sock.settimeout(timeout)
    return sock


def start_daemon_thread(target, args=()):
    th = threading.Thread(target=target, args=args)
    th.daemon = True
    th.start()
    return th


def closed_socket_ex(ex):
    if not hasattr(ex, "errno"):
        return False
    if hasattr(errno, "ECONNABORTED") and ex.errno == errno.ECONNABORTED:
        return True
    if hasattr(errno, "EBADFD") and ex.errno == errno.EBADFD:
        return True
    if hasattr(errno, "EBADF") and ex.errno == errno.EBADF:
        return True
    if hasattr(errno, "WSAEBADF") and ex.errno == errno.WSAEBADF:
        return True
    if hasattr(errno, "WSAEINTR") and ex.errno == errno.WSAEINTR:
        return True
    return False


def fix_codecs(codec_list = ["utf-8", "idna"]):
    missing_codecs = []
    for codec_name in codec_list:
        try:
            codecs.lookup(codec_name)
        except LookupError:
            missing_codecs.append(codec_name.lower())
    def search_codec(name):
        if name.lower() in missing_codecs:
            return codecs.CodecInfo(codecs.ascii_encode, codecs.ascii_decode, name="ascii")
    if missing_codecs:
        codecs.register(search_codec)


def check_docker_network():
    if not sys.platform.startswith("linux"):
        return
    if not os.path.exists("/.dockerenv"):
        return
    if not os.path.isfile("/sys/class/net/eth0/address"):
        return
    fo = open("/sys/class/net/eth0/address", "r")
    macaddr = fo.read().strip()
    fo.close()
    hostname = socket.gethostname()
    try:
        ipaddr = socket.gethostbyname(hostname)
    except socket.gaierror:
        Logger.warning("check-docket-network: Cannot resolve hostname `%s`" % hostname)
        return
    docker_macaddr = "02:42:" + ":".join(["%02x" % int(x) for x in ipaddr.split(".")])
    if macaddr == docker_macaddr:
        raise RuntimeError("Docker's `--net=host` option is required.")

    if not os.path.isfile("/proc/sys/kernel/osrelease"):
        return
    fo = open("/proc/sys/kernel/osrelease", "r")
    uname_r = fo.read().strip()
    fo.close()
    uname_r_sfx = uname_r.rsplit("-").pop()
    if uname_r_sfx.lower() in ["linuxkit", "wsl2"] and hostname.lower() == "docker-desktop":
        raise RuntimeError("Network from Docker Desktop is not supported.")


def split_url(url):
    m = re.match(
        r"^http://([^\[\]:/]+)(?:\:([0-9]+))?(/\S*)?$", url
    )
    if not m:
        raise ValueError("Unsupported URL: %s" % url)
    hostname, port_str, path = m.groups()
    port = 80
    if port_str:
        port = int(port_str)
    if not path:
        path = "/"
    return hostname, port, path


def full_url(u, refurl):
    if not u.startswith("/"):
        return u
    hostname, port, _ = split_url(refurl)
    return "http://%s:%d" % (hostname, port) + u


def addr_to_str(addr):
    return "%s:%d" % addr


def addr_to_uri(addr, udp=False):
    if udp:
        return "udp://%s:%d" % addr
    else:
        return "tcp://%s:%d" % addr


def validate_ip(s, err=True):
    try:
        socket.inet_aton(s)
        return True
    except (OSError, socket.error):
        if err:
            raise ValueError("Invalid IP address: %s" % s)
        return False


def validate_port(s, err=True):
    if str(s).isdigit() and int(s) in range(65536):
        return True
    if err:
        raise ValueError("Invalid port number: %s" % s)
    return False


def validate_addr_str(s, err=True):
    l = str(s).split(":", 1)
    if len(l) == 1:
        return True
    return validate_port(l[1], err)


def validate_positive(s, err=True):
    if str(s).isdigit() and int(s) > 0:
        return True
    if err:
        raise ValueError("Not a positive integer: %s" % s)
    return False


def validate_filepath(s, err=True):
    if os.path.isfile(s):
        return True
    if err:
        raise ValueError("File not found: %s" % s)
    return False


def ip_normalize(ipaddr):
    return socket.inet_ntoa(socket.inet_aton(ipaddr))


def natter_main(show_title = True):
    argp = argparse.ArgumentParser(
        description="Expose your port behind full-cone NAT to the Internet.", add_help=False
    )
    group = argp.add_argument_group("options")
    group.add_argument(
        "--version", "-V", action="version", version="Natter %s" % __version__,
        help="show the version of Natter and exit"
    )
    group.add_argument(
        "--help", action="help", help="show this help message and exit"
    )
    group.add_argument(
        "-v", action="store_true", help="verbose mode, printing debug messages"
    )
    group.add_argument(
        "-q", action="store_true", help="exit when mapped address is changed"
    )
    group.add_argument(
        "-u", action="store_true", help="UDP mode"
    )
    group.add_argument(
        "-U", action="store_true", help="enable UPnP/IGD discovery"
    )
    group.add_argument(
        "-k", type=int, metavar="<interval>", default=15,
        help="seconds between each keep-alive"
    )
    group.add_argument(
        "-s", metavar="<address>", action="append",
        help="hostname or address to STUN server"
    )
    group.add_argument(
        "-h", type=str, metavar="<address>", default=None,
        help="hostname or address to keep-alive server"
    )
    group.add_argument(
        "-e", type=str, metavar="<path>", default=None,
        help="script path for notifying mapped address"
    )
    group = argp.add_argument_group("bind options")
    group.add_argument(
        "-i", type=str, metavar="<interface>", default="0.0.0.0",
        help="network interface name or IP to bind"
    )
    group.add_argument(
        "-b", type=int, metavar="<port>", default=0,
        help="port number to bind"
    )
    group = argp.add_argument_group("forward options")
    group.add_argument(
        "-m", type=str, metavar="<method>", default=None,
        help="forward method, common values are 'iptables', 'nftables', "
             "'socat', 'gost' and 'socket'"
    )
    group.add_argument(
        "-t", type=str, metavar="<address>", default="0.0.0.0",
        help="IP address of forward target"
    )
    group.add_argument(
        "-p", type=int, metavar="<port>", default=0,
        help="port number of forward target"
    )
    group.add_argument(
        "-r", action="store_true", help="keep retrying until the port of forward target is open"
    )

    args = argp.parse_args()
    verbose = args.v
    udp_mode = args.u
    upnp_enabled = args.U
    interval = args.k
    stun_list = args.s
    keepalive_srv = args.h
    notify_sh = args.e
    bind_ip = args.i
    bind_interface = None
    bind_port = args.b
    method = args.m
    to_ip = args.t
    to_port = args.p
    keep_retry = args.r
    exit_when_changed = args.q

    sys.tracebacklimit = 0
    if verbose:
        sys.tracebacklimit = None
        Logger.set_level(Logger.DEBUG)

    validate_positive(interval)
    if stun_list:
        for stun_srv in stun_list:
            validate_addr_str(stun_srv)
    validate_addr_str(keepalive_srv)
    if notify_sh:
        validate_filepath(notify_sh)
    if not validate_ip(bind_ip, err=False):
        bind_interface = bind_ip
        bind_ip = "0.0.0.0"
    validate_port(bind_port)
    validate_ip(to_ip)
    validate_port(to_port)

    # Normalize IPv4 in dotted-decimal notation
    #   e.g. 10.1 -> 10.0.0.1
    bind_ip = ip_normalize(bind_ip)
    to_ip = ip_normalize(to_ip)

    if not stun_list:
        stun_list = [
            "fwa.lifesizecloud.com",
            "global.turn.twilio.com",
            "turn.cloudflare.com",
            "stun.isp.net.au",
            "stun.nextcloud.com",
            "stun.freeswitch.org",
            "stun.voip.blackberry.com",
            "stunserver.stunprotocol.org",
            "stun.sipnet.com",
            "stun.radiojar.com",
            "stun.sonetel.com",
            "stun.telnyx.com"
        ]
        if not udp_mode:
            stun_list = stun_list + [
                "turn.cloud-rtc.com:80"
            ]
        else:
            stun_list = [
                "stun.miwifi.com",
                "stun.chat.bilibili.com",
                "stun.hitv.com",
                "stun.cdnbye.com",
                "stun.douyucdn.cn:18000"
            ] + stun_list

    if not keepalive_srv:
        keepalive_srv = "www.baidu.com"
        if udp_mode:
            keepalive_srv = "119.29.29.29"

    stun_srv_list = []
    for item in stun_list:
        l = item.split(":", 2) + ["3478"]
        stun_srv_list.append((l[0], int(l[1])),)

    if udp_mode:
        l = keepalive_srv.split(":", 2) + ["53"]
        keepalive_host, keepalive_port = l[0], int(l[1])
    else:
        l = keepalive_srv.split(":", 2) + ["80"]
        keepalive_host, keepalive_port = l[0], int(l[1])

    # forward method defaults
    if not method:
        if to_ip == "0.0.0.0" and to_port == 0 and \
                bind_ip == "0.0.0.0" and bind_port == 0 and bind_interface is None:
            method = "test"
        elif to_ip == "0.0.0.0" and to_port == 0:
            method = "none"
        else:
            method = "socket"

    if method == "none":
        ForwardImpl = ForwardNone
    elif method == "test":
        ForwardImpl = ForwardTestServer
    elif method == "iptables":
        ForwardImpl = ForwardIptables
    elif method == "sudo-iptables":
        ForwardImpl = ForwardSudoIptables
    elif method == "iptables-snat":
        ForwardImpl = ForwardIptablesSnat
    elif method == "sudo-iptables-snat":
        ForwardImpl = ForwardSudoIptablesSnat
    elif method == "nftables":
        ForwardImpl = ForwardNftables
    elif method == "sudo-nftables":
        ForwardImpl = ForwardSudoNftables
    elif method == "nftables-snat":
        ForwardImpl = ForwardNftablesSnat
    elif method == "sudo-nftables-snat":
        ForwardImpl = ForwardSudoNftablesSnat
    elif method == "socat":
        ForwardImpl = ForwardSocat
    elif method == "gost":
        ForwardImpl = ForwardGost
    elif method == "socket":
        ForwardImpl = ForwardSocket
    else:
        raise ValueError("Unknown method name: %s" % method)
    #
    #  Natter
    #
    if show_title:
        Logger.info("Natter v%s" % __version__)
        if len(sys.argv) == 1:
            Logger.info("Tips: Use `--help` to see help messages")

    check_docker_network()

    forwarder = ForwardImpl()
    port_test = PortTest()

    stun = StunClient(stun_srv_list, bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
    natter_addr, outer_addr = stun.get_mapping()
    # set actual ip and port for keep-alive socket to bind, instead of zero
    bind_ip, bind_port = natter_addr

    keep_alive = KeepAlive(keepalive_host, keepalive_port, bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
    keep_alive.keep_alive()

    # get the mapped address again after the keep-alive connection is established
    outer_addr_prev = outer_addr
    natter_addr, outer_addr = stun.get_mapping()
    if outer_addr != outer_addr_prev:
        Logger.warning("Network is unstable, or not full cone")

    # set actual ip of localhost for correct forwarding
    if socket.inet_aton(to_ip) in [socket.inet_aton("127.0.0.1"), socket.inet_aton("0.0.0.0")]:
        to_ip = natter_addr[0]

    # if not specified, the target port is set to be the same as the outer port
    if not to_port:
        to_port = outer_addr[1]

    # some exceptions: ForwardNone and ForwardTestServer are not real forward methods,
    # so let target ip and port equal to natter's
    if ForwardImpl in (ForwardNone, ForwardTestServer):
        to_ip, to_port = natter_addr

    to_addr = (to_ip, to_port)
    forwarder.start_forward(natter_addr[0], natter_addr[1], to_addr[0], to_addr[1], udp=udp_mode)
    NatterExit.set_atexit(forwarder.stop_forward)

    # UPnP
    upnp = None
    upnp_router = None
    upnp_ready = False

    if upnp_enabled:
        upnp = UPnPClient(bind_ip=natter_addr[0], interface=bind_interface)
        Logger.info()
        Logger.info("Scanning UPnP Devices...")
        try:
            upnp_router = upnp.discover_router()
        except (OSError, socket.error, ValueError) as ex:
            Logger.error("upnp: failed to discover router: %s" % ex)

    if upnp_router:
        Logger.info("[UPnP] Found router %s" % upnp_router.ipaddr)
        try:
            upnp.forward("", bind_port, bind_ip, bind_port, udp=udp_mode, duration=interval*3)
        except (OSError, socket.error, ValueError) as ex:
            Logger.error("upnp: failed to forward port: %s" % ex)
        else:
            upnp_ready = True

    # Display route information
    Logger.info()
    route_str = ""
    if ForwardImpl not in (ForwardNone, ForwardTestServer):
        route_str += "%s <--%s--> " % (addr_to_uri(to_addr, udp=udp_mode), method)
    route_str += "%s <--Natter--> %s" % (
        addr_to_uri(natter_addr, udp=udp_mode), addr_to_uri(outer_addr, udp=udp_mode)
    )
    Logger.info(route_str)
    Logger.info()

    # Test mode notice
    if ForwardImpl == ForwardTestServer:
        Logger.info("Test mode in on.")
        Logger.info("Please check [ %s://%s ]" % ("udp" if udp_mode else "http", addr_to_str(outer_addr)))
        Logger.info()

    # Call notification script
    if notify_sh:
        protocol = "udp" if udp_mode else "tcp"
        inner_ip, inner_port = to_addr if method else natter_addr
        outer_ip, outer_port = outer_addr
        Logger.info("Calling script: %s" % notify_sh)
        subprocess.call([
            os.path.abspath(notify_sh), protocol, str(inner_ip), str(inner_port), str(outer_ip), str(outer_port)
        ], shell=False)

    # Display check results, TCP only
    if not udp_mode:
        ret1 = port_test.test_lan(to_addr, info=True)
        ret2 = port_test.test_lan(natter_addr, info=True)
        ret3 = port_test.test_lan(outer_addr, source_ip=natter_addr[0], interface=bind_interface, info=True)
        ret4 = port_test.test_wan(outer_addr, source_ip=natter_addr[0], interface=bind_interface, info=True)
        if ret1 == -1:
            Logger.warning("!! Target port is closed !!")
        elif ret1 == 1 and ret3 == ret4 == -1:
            Logger.warning("!! Hole punching failed !!")
        elif ret3 == 1 and ret4 == -1:
            Logger.warning("!! You may be behind a firewall !!")
        Logger.info()
        # retry
        if keep_retry and ret1 == -1:
            Logger.info("Retry after %d seconds..." % interval)
            time.sleep(interval)
            forwarder.stop_forward()
            raise NatterRetryException("Target port is closed")
    #
    #  Main loop
    #
    need_recheck = False
    cnt = 0
    while True:
        # force recheck every 20th loop
        cnt = (cnt + 1) % 20
        if cnt == 0:
            need_recheck = True
        if need_recheck:
            Logger.debug("Start recheck")
            need_recheck = False
            # check LAN port first
            if udp_mode or port_test.test_lan(outer_addr, source_ip=natter_addr[0], interface=bind_interface) == -1:
                # then check through STUN
                _, outer_addr_curr = stun.get_mapping()
                if outer_addr_curr != outer_addr:
                    forwarder.stop_forward()
                    # exit or retry
                    if exit_when_changed:
                        Logger.info("Natter is exiting because mapped address has changed")
                        raise NatterExitException("Mapped address has changed")
                    raise NatterRetryException("Mapped address has changed")
        # end of recheck
        ts = time.time()
        try:
            keep_alive.keep_alive()
        except (OSError, socket.error) as ex:
            if udp_mode:
                Logger.debug("keep-alive: UDP response not received: %s" % ex)
            else:
                Logger.error("keep-alive: connection broken: %s" % ex)
            keep_alive.reset()
            need_recheck = True
        if upnp_ready:
            try:
                upnp.renew()
            except (OSError, socket.error) as ex:
                Logger.error("upnp: failed to renew upnp: %s" % ex)
        sleep_sec = interval - (time.time() - ts)
        if sleep_sec > 0:
            time.sleep(sleep_sec)


def main():
    signal.signal(signal.SIGTERM, lambda s,f:exit(143))
    fix_codecs()
    show_title = True
    while True:
        try:
            natter_main(show_title)
        except NatterRetryException:
            pass
        except (NatterExitException, KeyboardInterrupt):
            sys.exit()
        show_title = False


if __name__ == "__main__":
    main()
