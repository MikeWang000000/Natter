import threading
import socket
import struct
import codecs
import json
import time
import sys
import os

__version__ = "0.9.0"


# Fix OpenWRT Python codecs issues:
#   Always fallback to ASCII when specified codec is not available.
try:
    codecs.lookup("idna")
    codecs.lookup("utf-8")
except LookupError:
    def search_codec(_):
        return codecs.CodecInfo(codecs.ascii_encode, codecs.ascii_decode, name="ascii")
    codecs.register(search_codec)


def get_free_port(udp=False):
    if udp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Not all OS have a SO_REUSEPORT option
    if "SO_REUSEPORT" in dir(socket):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", 0))
    ret = sock.getsockname()[1]
    sock.close()
    return ret


def test_port_open(dst_addr, timeout = 3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex(dst_addr)
    sock.close()
    return result == 0


class Logger(object):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4

    def __init__(self, level = INFO, files = (sys.stderr,)):
        self.level = level
        self.files = files

    def debug(self, msg):
        if self.level <= Logger.DEBUG:
            for fo in self.files:
                fo.write("[DEBUG] - " + str(msg) + "\n")
                fo.flush()

    def info(self, msg):
        if self.level <= Logger.INFO:
            for fo in self.files:
                fo.write("[INFO] - " + str(msg) + "\n")
                fo.flush()

    def warning(self, msg):
        if self.level <= Logger.WARNING:
            for fo in self.files:
                fo.write("[WARNING] - " + str(msg) + "\n")
                fo.flush()

    def error(self, msg):
        if self.level <= Logger.ERROR:
            for fo in self.files:
                fo.write("[ERROR] - " + str(msg) + "\n")
                fo.flush()

    def script(self, msg):
        if self.level <= Logger.INFO:
            for fo in self.files:
                fo.write(msg)
                fo.flush()

class StunClient(object):
    # Note: IPv4 Only.
    # Reference:
    #     https://www.rfc-editor.org/rfc/rfc3489
    #     https://www.rfc-editor.org/rfc/rfc5389
    #     https://www.rfc-editor.org/rfc/rfc8489

    # Servers in this list must be compatible with rfc5389 or rfc8489
    stun_server_tcp = [
        "fwa.lifesizecloud.com",
        "stun.isp.net.au",
        "stun.freeswitch.org",
        "stun.voip.blackberry.com",
        "stun.nextcloud.com",
        "stun.stunprotocol.org",
        "stun.sipnet.com",
        "stun.radiojar.com",
        "stun.sonetel.com",
        "stun.voipgate.com"
    ]
    # Servers in this list must be compatible with rfc3489, with "change IP" and "change port" functions available
    stun_server_udp = [
        "stun.miwifi.com",
        "stun.qq.com"
    ]

    _stun_ip_tcp = []
    _stun_ip_udp = []

    MTU         = 1500
    STUN_PORT   = 3478
    MAGIC_COOKIE    = 0x2112a442
    BIND_REQUEST    = 0x0001
    BIND_RESPONSE   = 0x0101
    FAMILY_IPV4     = 0x01
    FAMILY_IPV6     = 0x02
    CHANGE_PORT     = 0x0002
    CHANGE_IP       = 0x0004
    ATTRIB_MAPPED_ADDRESS      = 0x0001
    ATTRIB_CHANGE_REQUEST      = 0x0003
    ATTRIB_XOR_MAPPED_ADDRESS  = 0x0020
    NAT_OPEN_INTERNET    = 0
    NAT_FULL_CONE        = 1
    NAT_RESTRICTED       = 2
    NAT_PORT_RESTRICTED  = 3
    NAT_SYMMETRIC        = 4
    NAT_SYM_UDP_FIREWALL = 5

    def __init__(self, source_ip = "0.0.0.0", logger = None):
        self.logger = logger if logger else Logger()
        self.source_ip = source_ip
        if not self.check_reuse_ability():
            raise OSError("This OS or Python does not support reusing ports!")
        if not self._stun_ip_tcp or not self._stun_ip_udp:
            self.logger.info("Getting STUN server IP...")
            for hostname in self.stun_server_tcp:
                self._stun_ip_tcp.extend(
                    ip for ip in self.resolve_hostname(hostname) if ip not in self._stun_ip_tcp
                )
            for hostname in self.stun_server_udp:
                self._stun_ip_udp.extend(
                    ip for ip in self.resolve_hostname(hostname) if ip not in self._stun_ip_udp
                )
        if not self._stun_ip_tcp or not self._stun_ip_udp:
            raise Exception("No public STUN server is avaliable. Please check your Internet connection.")

    def check_reuse_ability(self):
        try:
            # A simple test: listen on the same port
            test_port = get_free_port()
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if "SO_REUSEPORT" in dir(socket):
                s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s1.bind(("", test_port))
            s1.listen(5)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if "SO_REUSEPORT" in dir(socket):
                s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s2.bind(("", test_port))
            s2.listen(5)
            s1.close()
            s2.close()
            return True
        except OSError as e:
            self.logger.debug("Cannot reuse: %s: %s" % (e.__class__.__name__, e))
            return False

    def resolve_hostname(self, hostname):
        self.logger.debug("Resolving hostname [%s]..." % hostname)
        try:
            host, alias, ip_addresses = socket.gethostbyname_ex(hostname)
            return ip_addresses
        except Exception as e:
            self.logger.debug("Cannot resolve: %s: %s" % (e.__class__.__name__, e))
            return []

    def random_tran_id(self, use_magic_cookie = False):
        if use_magic_cookie:
            # Compatible with rfc3489, rfc5389 and rfc8489
            return struct.pack("!L", self.MAGIC_COOKIE) + os.urandom(12)
        else:
            # Compatible with rfc3489
            return os.urandom(16)

    def pack_stun_message(self, msg_type, tran_id, payload = b""):
        return struct.pack("!HH", msg_type, len(payload)) + tran_id + payload

    def unpack_stun_message(self, data):
        msg_type, msg_length = struct.unpack("!HH", data[:4])
        tran_id = data[4:20]
        payload = data[20:20 + msg_length]
        return msg_type, tran_id, payload

    def extract_mapped_addr(self, payload):
        while payload:
            attrib_type, attrib_length = struct.unpack("!HH", payload[:4])
            attrib_value = payload[4:4 + attrib_length]
            payload = payload[4 + attrib_length:]
            if attrib_type == self.ATTRIB_MAPPED_ADDRESS:
                _, family, port = struct.unpack("!BBH", attrib_value[:4])
                if family == self.FAMILY_IPV4:
                    ip = socket.inet_ntoa(attrib_value[4:8])
                    return ip, port
            elif attrib_type == self.ATTRIB_XOR_MAPPED_ADDRESS:
                # rfc5389 and rfc8489
                _, family, xor_port = struct.unpack("!BBH", attrib_value[:4])
                if family == self.FAMILY_IPV4:
                    xor_iip, = struct.unpack("!L", attrib_value[4:8])
                    ip = socket.inet_ntoa(struct.pack("!L", self.MAGIC_COOKIE ^ xor_iip))
                    port = (self.MAGIC_COOKIE >> 16) ^ xor_port
                    return ip, port
        return None

    def tcp_test(self, stun_host, source_port, timeout = 1):
        # rfc5389 and rfc8489 only
        self.logger.debug("Trying TCP STUN: %s" % stun_host)
        tran_id = self.random_tran_id(use_magic_cookie = True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if "SO_REUSEPORT" in dir(socket):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.settimeout(timeout)
            sock.bind((self.source_ip, source_port))
            sock.connect((stun_host, self.STUN_PORT))
            data = self.pack_stun_message(self.BIND_REQUEST, tran_id)
            sock.sendall(data)
            buf = sock.recv(self.MTU)
            msg_type, msg_id, payload = self.unpack_stun_message(buf)
            if tran_id == msg_id and msg_type == self.BIND_RESPONSE:
                source_addr  = sock.getsockname()
                mapped_addr = self.extract_mapped_addr(payload)
                ret = source_addr, mapped_addr
                self.logger.debug("(TCP) %s says: %s" % (stun_host, mapped_addr))
            else:
                ret = None
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except Exception as e:
            self.logger.debug("Cannot do TCP STUN test: %s: %s" % (e.__class__.__name__, e))
            sock.close()
            ret = None
        return ret

    def udp_test(self, stun_host, source_port, change_ip = False, change_port = False, timeout = 1, repeat = 3, custom_sock = None):
        # Note:
        #   Assuming STUN is being multiplexed with other protocols,
        #   the packet must be inspected to check if it is a STUN packet.
        #   Parameter source_port has no effect when custom_sock is set
        self.logger.debug("Trying UDP STUN: %s (change ip:%d/port:%d)" % (stun_host, change_ip, change_port))
        time_start = time.time()
        tran_id = self.random_tran_id()
        if custom_sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = custom_sock
        origin_timeout = sock.gettimeout()
        try:
            if sock is not custom_sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if "SO_REUSEPORT" in dir(socket):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind((self.source_ip, source_port))
            flags = 0
            if change_ip:
                flags |= self.CHANGE_IP
            if change_port:
                flags |= self.CHANGE_PORT
            if flags:
                payload = struct.pack("!HHL", self.ATTRIB_CHANGE_REQUEST, 0x4, flags)
                data = self.pack_stun_message(self.BIND_REQUEST, tran_id, payload)
            else:
                data = self.pack_stun_message(self.BIND_REQUEST, tran_id)
            # Send packets repeatedly to avoid packet loss.
            for _ in range(repeat):
                sock.sendto(data, (stun_host, self.STUN_PORT))
            while True:
                time_left = time_start + timeout - time.time()
                if time_left <= 0:
                    raise socket.timeout("timed out")
                sock.settimeout(time_left)
                buf, recv_addr = sock.recvfrom(self.MTU)
                recv_host, recv_port = recv_addr
                # Check the STUN packet.
                if len(buf) < 20:
                    continue
                msg_type, msg_id, payload = self.unpack_stun_message(buf)
                if tran_id != msg_id or msg_type != self.BIND_RESPONSE:
                    continue
                source_addr  = sock.getsockname()
                mapped_addr  = self.extract_mapped_addr(payload)
                ip_changed   = (recv_host != self.STUN_PORT)
                port_changed = (recv_port != self.STUN_PORT)
                self.logger.debug("(UDP) %s says: %s" % (recv_addr, mapped_addr))
                return source_addr, mapped_addr, ip_changed, port_changed
        except Exception as e:
            self.logger.debug("Cannot do UDP STUN test: %s: %s" % (e.__class__.__name__, e))
            return None
        finally:
            sock.settimeout(origin_timeout)
            if sock is not custom_sock:
                sock.close()

    def get_tcp_mapping(self, source_port):
        server_ip = first = self._stun_ip_tcp[0]
        while True:
            ret = self.tcp_test(server_ip, source_port)
            if ret is None:
                # Server unavailable, put it at the end of the list.
                self._stun_ip_tcp.append(self._stun_ip_tcp.pop(0))
                server_ip = self._stun_ip_tcp[0]
                if server_ip == first:
                    raise Exception("No public STUN server is avaliable. Please check your Internet connection.")
            else:
                source_addr, mapped_addr = ret
                return source_addr, mapped_addr

    def get_udp_mapping(self, source_port, custom_sock = None):
        server_ip = first = self._stun_ip_udp[0]
        while True:
            ret = self.udp_test(server_ip, source_port, custom_sock = custom_sock)
            if ret is None:
                # Server unavailable, put it at the end of the list.
                self._stun_ip_udp.append(self._stun_ip_udp.pop(0))
                server_ip = self._stun_ip_udp[0]
                if server_ip == first:
                    raise Exception("No public STUN server is avaliable. Please check your Internet connection.")
            else:
                source_addr, mapped_addr, ip_changed, port_changed = ret
                return source_addr, mapped_addr

    def check_nat_type(self, source_port = 0):
        # Like classic STUN (rfc3489). Detect NAT behavior for UDP.
        # Modified from rfc3489. Requires at least two STUN servers.
        ret_test1_1 = None
        ret_test1_2 = None
        ret_test2 = None
        ret_test3 = None
        if source_port == 0:
            source_port = get_free_port(udp=True)

        for server_ip in self._stun_ip_udp:
            ret = self.udp_test(server_ip, source_port, change_ip=False, change_port=False)
            if ret is None:
                self.logger.debug("No response. Trying another STUN server...")
                continue
            if ret_test1_1 is None:
                ret_test1_1 = ret
                continue
            ret_test1_2 = ret
            ret = self.udp_test(server_ip, source_port, change_ip=True, change_port=True)
            if ret is not None:
                source_addr, mapped_addr, ip_changed, port_changed = ret
                if not ip_changed or not port_changed:
                    self.logger.debug("Trying another STUN server because current server do not have another available IP or port...")
                    continue
            ret_test2 = ret
            ret_test3 = self.udp_test(server_ip, source_port, change_ip=False, change_port=True)
            break
        else:
            raise Exception("UDP Blocked or not enough STUN servers available.")

        source_addr_1_1, mapped_addr_1_1, _, _ = ret_test1_1
        source_addr_1_2, mapped_addr_1_2, _, _ = ret_test1_2
        if mapped_addr_1_1 != mapped_addr_1_2:
            return StunClient.NAT_SYMMETRIC
        if source_addr_1_1 == mapped_addr_1_1:
            if ret_test2 is not None:
                return StunClient.NAT_OPEN_INTERNET
            else:
                return StunClient.NAT_SYM_UDP_FIREWALL
        else:
            if ret_test2 is not None:
                return StunClient.NAT_FULL_CONE
            else:
                if ret_test3 is not None:
                    return StunClient.NAT_RESTRICTED
                else:
                    return StunClient.NAT_PORT_RESTRICTED

    def is_tcp_cone(self, source_port = 0):
        # Detect NAT behavior for TCP. Requires at least three STUN servers for accuracy.
        if source_port == 0:
            source_port = get_free_port()
        mapped_addr_first = None
        count = 0
        for server_ip in self._stun_ip_tcp:
            if count >= 3:
                return True
            ret = self.tcp_test(server_ip, source_port)
            if ret is not None:
                source_addr, mapped_addr = ret
                if mapped_addr_first is not None and mapped_addr != mapped_addr_first:
                    return False
                mapped_addr_first = ret[1]
                count += 1
        raise Exception("Not enough STUN servers available.")


class HttpTestServer(object):
    # HTTP Server for testing purpose
    # On success, you can see the text "It works!".

    def __init__(self, listen_addr, logger = None):
        self.logger = logger if logger else Logger()
        self.running = False
        self.listen_addr = listen_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if "SO_REUSEPORT" in dir(socket):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    def run(self):
        self.running = True
        self.sock.bind(self.listen_addr)
        self.sock.listen(5)
        while self.running:
            try:
                conn, addr = self.sock.accept()
                self.logger.debug("HttpTestServer got client %s" % (addr,))
            except Exception:
                return
            try:
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\n")
                conn.sendall(b"Content-Type: text/html\r\n")
                conn.sendall(b"\r\n")
                conn.sendall(b"<h1>It works!</h1><hr/>Natter\r\n")
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            finally:
                conn.close()

    def start(self):
        self.logger.info("HttpTestServer starting...")
        threading.Thread(target=self.run).start()

    def stop(self):
        self.logger.info("HttpTestServer stopping...")
        self.running = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        sock.connect_ex(self.listen_addr)
        sock.close()
        self.sock.close()


class TCPForwarder(object):
    def __init__(self, listen_addr, forward_addr, logger = None):
        self.listen_sock = None
        self.listen_addr = listen_addr
        self.forward_addr = forward_addr
        self.logger = logger if logger else Logger()
        self.stopped = False

    def run(self):
        self.stopped = False
        self.listen_sock = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if "SO_REUSEPORT" in dir(socket):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(self.listen_addr)
        s.settimeout(None)
        s.listen(5)
        while not self.stopped:
            try:
                client_sock, client_addr = s.accept()
                self.logger.debug("Got client: %s" % (client_addr,))
            except Exception as e:
                self.logger.debug("Cannot accept client: %s: %s" % (e.__class__.__name__, e))
                continue
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                server_sock.settimeout(3)
                server_sock.connect(self.forward_addr)
                server_sock.settimeout(None)
            except Exception as e:
                self.logger.debug("Cannot connect to forward_addr: %s: %s" % (e.__class__.__name__, e))
                client_sock.close()
                server_sock.close()
            threading.Thread(target=self._forward, args=(client_sock, server_sock)).start()
            threading.Thread(target=self._forward, args=(server_sock, client_sock)).start()

    @staticmethod
    def _forward(s1, s2):
        data = "..."
        try:
            while data:
                data = s1.recv(1024)
                if data:
                    s2.sendall(data)
                else:
                    s1.shutdown(socket.SHUT_RD)
                    s2.shutdown(socket.SHUT_WR)
        except Exception:
            s1.close()
            s2.close()

    def start(self):
        threading.Thread(target=self.run).start()

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        sock.connect_ex(self.listen_addr)
        sock.close()
        self.listen_sock.close()
        self.listen_sock = None


class UDPForwarder(object):
    def __init__(self, listen_sock, listen_addr, forward_addr, logger):
        self.listen_sock = listen_sock
        self.listen_addr = listen_addr
        self.forward_addr = forward_addr
        self.logger = logger if logger else Logger()
        self.stopped = False
        self.client_last = {}
        self.srv_socks = {}
        self.udp_timeout = 90

    def run(self):
        self.stopped = False
        while not self.stopped:
            try:
                data, client_addr = self.listen_sock.recvfrom(2048)
            except socket.timeout:
                continue
            self.client_last[client_addr] = time.time()
            server_sock = self.srv_socks.get(client_addr)
            if data and server_sock is None:
                self.logger.debug("Got client: %s" % (client_addr,))
                self.srv_socks[client_addr] = server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                threading.Thread(target=self._udp_forward, args=(client_addr,)).start()
            if server_sock:
                server_sock.sendto(data, self.forward_addr)

    def _udp_forward(self, client_addr):
        server_sock = self.srv_socks[client_addr]
        server_sock.settimeout(self.udp_timeout)
        data = "..."
        try:
            while data:
                time_diff = time.time() - self.client_last[client_addr]
                if time_diff > self.udp_timeout:
                    server_sock.sendto("", self.forward_addr)
                    raise socket.timeout("client timeout")
                data, server_addr = server_sock.recvfrom(2048)
                self.listen_sock.sendto(data, client_addr)
        except Exception:
            pass
        finally:
            server_sock.close()
            del self.client_last[client_addr]
            del self.srv_socks[client_addr]

    def start(self):
        threading.Thread(target=self.run).start()

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"", self.listen_addr)
        sock.close()


class NatterTCP(object):
    def __init__(self, source_addr, forward_addr, keep_alive_host, logger = None):
        self.logger = logger if logger else Logger()
        self.stun_client = StunClient(source_addr[0], logger = self.logger)
        self.forwarder = TCPForwarder(source_addr, forward_addr, logger = self.logger)
        self.source_addr = source_addr
        self.forward_addr = forward_addr
        self.keep_alive_host = keep_alive_host
        self.keep_alive_sock = None
        self.forward_running = False

    def keep_alive(self, timeout = 1):
        # Note:
        #   The only purpose of this method is to keep the outgoing TCP connection from being closed.
        #   Natter will send a HEAD HTTP request with keep-alive header to the target host.
        #   We don't want to disturb the host too much, and meanwhile we will get minimal return data this way.
        s = self.keep_alive_sock
        try:
            if s is None:
                self.keep_alive_sock = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if "SO_REUSEPORT" in dir(socket):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind(self.source_addr)
                s.settimeout(timeout)
                s.connect((self.keep_alive_host, 80))
            s.sendall(b"HEAD / HTTP/1.1\r\n")
            s.sendall(b"Host: %s\r\n" % self.keep_alive_host.encode())
            s.sendall(b"User-Agent: Mozilla/5.0 (%s; %s) Natter\r\n" % (sys.platform.encode(), os.name.encode()))
            s.sendall(b"Accept: */*\r\n")
            s.sendall(b"Connection: keep-alive\r\n")
            s.sendall(b"\r\n")
            received = b""
            conn_closed = False
            while b"\r\n\r\n" not in received and not conn_closed:
                received = received[-4:] + s.recv(4096)
                conn_closed = (len(received) == 0)
            if not conn_closed:
                self.logger.debug("[%s] Keep-Alive OK!" % time.asctime())
                return True
            else:
                raise socket.error("Server closed connection")
        except Exception as e:
            self.logger.debug("Cannot TCP keep-alive: %s: %s" % (e.__class__.__name__, e))
            if self.keep_alive_sock is None:
                return False
            try:
                # Explicitly shut down the socket
                self.keep_alive_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.keep_alive_sock.close()
            # Set self.keep_alive_sock to None so the keep-alive connection will be re-established the
            # next time keep_alive() is called.
            self.keep_alive_sock = None
            return False

    def get_mapping(self):
        try:
            return self.stun_client.get_tcp_mapping(self.source_addr[1])
        except Exception as e:
            self.logger.debug("Cannot get TCP mapping: %s: %s" % (e.__class__.__name__, e))
            return None

    def start_forward(self):
        if not self.forward_running:
            self.forwarder.start()
            self.forward_running = True

    def stop_forward(self):
        if self.forward_running:
            self.forwarder.stop()
            self.forward_running = False


class NatterUDP(object):
    def __init__(self, source_addr, forward_addr, keep_alive_host, logger = None):
        self.base_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.base_sock.bind(source_addr)
        self.logger = logger if logger else Logger()
        self.stun_client = StunClient(source_addr[0], logger = self.logger)
        self.forwarder = UDPForwarder(self.base_sock, source_addr, forward_addr, logger = self.logger)
        self.source_addr = source_addr
        self.forward_addr = forward_addr
        self.keep_alive_host = keep_alive_host
        self.forward_running = False

    def keep_alive(self):
        # Note:
        #   Natter will send a message to port 30003 of the target's UDP, regardless of
        #   whether the target replies to it.
        try:
            self.base_sock.sendto(b"hello", (self.keep_alive_host, 30003))
            self.logger.debug("[%s] Keep-Alive OK!" % time.asctime())
            return True
        except Exception as e:
            self.logger.debug("Cannot UDP keep-alive: %s: %s" % (e.__class__.__name__, e))
            return False

    def get_mapping(self):
        fwd = self.forward_running
        if fwd:
            # Temporarily stop port forwarding to avoid interference.
            self.stop_forward()
        try:
            return self.stun_client.get_udp_mapping(self.source_addr[1], custom_sock = self.base_sock)
        except Exception as e:
            self.logger.debug("Cannot get UDP mapping: %s: %s" % (e.__class__.__name__, e))
            return None
        finally:
            if fwd:
                self.start_forward()

    def start_forward(self):
        if not self.forward_running:
            self.forwarder.start()
            self.forward_running = True

    def stop_forward(self):
        if self.forward_running:
            self.forwarder.stop()
            self.forward_running = False


class Natter(object):
    def __init__(self, keep_alive_host, interval = 10, logger = None):
        self.logger = logger if logger else Logger()
        self.nr_list = []
        self.keep_alive_host = keep_alive_host
        self.interval = interval
        self.hook_command = None
        self.status_file = None
        self.maps = {"tcp": {}, "udp": {}}

    def __del__(self):
        self.close()

    def add_tcp_open_port(self, source_addr):
        self.nr_list.append(NatterTCP(source_addr, None, self.keep_alive_host, logger = self.logger))

    def add_udp_open_port(self, source_addr):
        self.nr_list.append(NatterUDP(source_addr, None, self.keep_alive_host, logger = self.logger))

    def add_tcp_forward_port(self, forward_addr):
        source_addr = ("0.0.0.0", get_free_port())
        self.nr_list.append(NatterTCP(source_addr, forward_addr, self.keep_alive_host, logger = self.logger))

    def add_udp_forward_port(self, forward_addr):
        source_addr = ("0.0.0.0", get_free_port(udp=True))
        self.nr_list.append(NatterUDP(source_addr, forward_addr, self.keep_alive_host, logger = self.logger))

    def set_hook(self, hook_command):
        self.hook_command = hook_command

    def set_status_file(self, status_file_path):
        self.status_file = open(status_file_path, "w+")

    def execute_hook(self, inner_addr, outer_addr, protocol, command):
        inner_ip, inner_port = inner_addr
        outer_ip, outer_port = outer_addr
        command = command.replace("{inner_ip}", str(inner_ip))
        command = command.replace("{inner_port}", str(inner_port))
        command = command.replace("{outer_ip}", str(outer_ip))
        command = command.replace("{outer_port}", str(outer_port))
        command = command.replace("{protocol}", str(protocol))
        script_log = os.popen(command)
        self.logger.script(script_log.read())

    def update_status_file(self):
        status = {"tcp": [], "udp": []}
        for protocol in status:
            for inner_ip, inner_port in self.maps[protocol]:
                outer_ip, outer_port = self.maps[protocol][inner_ip, inner_port]
                record = {
                    "inner": "%s:%d" % (inner_ip, inner_port),
                    "outer": "%s:%d" % (outer_ip, outer_port),
                }
                status[protocol].append(record)
        self.status_file.seek(0)
        self.status_file.truncate(0)
        json.dump(status, self.status_file, indent = 4)
        self.status_file.flush()

    def _update_status(self, nr):
        mapping = nr.get_mapping()
        if not mapping:
            return
        # update mapping dict
        protocol = "tcp" if type(nr) is NatterTCP else "udp"
        inner_addr, outer_addr = mapping
        if nr.forward_addr:
            inner_addr = nr.forward_addr
        self.maps[protocol][inner_addr] = outer_addr
        self.logger.info(">>> [%s] %s -> %s <<<" % (protocol.upper(), inner_addr, outer_addr))
        # update status file
        if self.status_file:
            self.update_status_file()
        # excute hook command
        if self.hook_command:
            threading.Thread(
                target = self.execute_hook,
                args = (inner_addr, outer_addr, protocol, self.hook_command)
            ).start()

    def run(self):
        last_ok = {}
        for nr in self.nr_list:
            last_ok[nr] = False
            nr.keep_alive()
            if nr.forward_addr:
                nr.start_forward()
        while True:
            for nr in self.nr_list:
                if not last_ok[nr]:
                    self._update_status(nr)
                last_ok[nr] = nr.keep_alive()
            time.sleep(self.interval)
            self.logger.debug("Current threads: %s" % threading.active_count())

    @staticmethod
    def from_config(config_path):
        fo = open(config_path)
        config = json.load(fo)
        fo.close()

        log_level = {
            "debug": Logger.DEBUG,
            "info": Logger.INFO,
            "warning": Logger.WARNING,
            "error": Logger.ERROR
        }[config["logging"]["level"]]
        log_file = config["logging"]["log_file"]
        if log_file:
            logger = Logger(log_level, files=(sys.stderr, open(log_file, "a")))
        else:
            logger = Logger(log_level)

        StunClient.stun_server_tcp = config["stun_server"]["tcp"]
        StunClient.stun_server_udp = config["stun_server"]["udp"]

        keep_alive_host = config["keep_alive"]

        natter = Natter(keep_alive_host, interval=10, logger=logger)
        hook = config["status_report"]["hook"]
        if hook:
            natter.set_hook(hook)
        statfile = config["status_report"]["status_file"]
        if statfile:
            natter.set_status_file(statfile)

        for addr_str in config["open_port"]["tcp"]:
            ip, port_str = addr_str.split(":")
            port = int(port_str)
            natter.add_tcp_open_port((ip, port))

        for addr_str in config["open_port"]["udp"]:
            ip, port_str = addr_str.split(":")
            port = int(port_str)
            natter.add_udp_open_port((ip, port))

        for addr_str in config["forward_port"]["tcp"]:
            ip, port_str = addr_str.split(":")
            port = int(port_str)
            natter.add_tcp_forward_port((ip, port))

        for addr_str in config["forward_port"]["udp"]:
            ip, port_str = addr_str.split(":")
            port = int(port_str)
            natter.add_udp_forward_port((ip, port))

        return natter
    
    def close(self):
        for nr in self.nr_list:
            nr.stop_forward()
        if self.status_file:
            self.status_file.close()

def print_nat(source_ip = "0.0.0.0", source_port = 0):
    logger = Logger()
    stun_client = StunClient(source_ip, logger = logger)
    nat_type = stun_client.check_nat_type(source_port)
    if nat_type == StunClient.NAT_OPEN_INTERNET:
        nat_type_txt = "Open Internet"
    elif nat_type == StunClient.NAT_SYM_UDP_FIREWALL:
        nat_type_txt = "Symmetric UDP firewall"
    elif nat_type == StunClient.NAT_FULL_CONE:
        nat_type_txt = "Full cone (NAT 1)"
    elif nat_type == StunClient.NAT_RESTRICTED:
        nat_type_txt = "Restricted (NAT 2)"
    elif nat_type == StunClient.NAT_PORT_RESTRICTED:
        nat_type_txt = "Port restricted (NAT 3)"
    elif nat_type == StunClient.NAT_SYMMETRIC:
        nat_type_txt = "Symmetric (NAT 4)"
    else:
        nat_type_txt = "Unknown"
    logger.info("NAT Type for UDP: [ %s ]" % nat_type_txt)
    if nat_type == StunClient.NAT_OPEN_INTERNET:
        logger.warning("It looks like you are not in a NAT network, so there is no need to use this tool.")
    elif nat_type != StunClient.NAT_FULL_CONE:
        logger.warning("The NAT type of your network is not full cone (NAT 1). TCP hole punching may fail.")

    logger.info("Checking NAT Type for TCP...")
    if stun_client.is_tcp_cone():
        logger.info("NAT Type for TCP: [ Cone NAT ]")
    else:
        logger.info("NAT Type for TCP: [ Symmetric ]")
        logger.warning("You cannot perform TCP hole punching in a symmetric NAT network.")
        return


def main():
    try:
        config_path = ""
        src_host = "0.0.0.0"
        src_port = -1
        verbose = False
        test_http = False
        use_config = False
        check_nat = False
        l = []
        for arg in sys.argv[1:]:
            if arg[0] == "-":
                if arg == "-c":
                    use_config = True
                elif arg == "-v":
                    verbose = True
                elif arg == "-t":
                    test_http = True
                elif arg == "--check-nat":
                    check_nat = True
                else:
                    raise ValueError
            else:
                l.append(arg)
        if not use_config:
            if len(l) == 0 and check_nat:
                src_port = 0
            elif len(l) == 1:
                src_port = int(l[0])
            elif len(l) == 2:
                src_host = l[0]
                src_port = int(l[1])
            else:
                raise ValueError
        else:
            if len(l) == 1:
                config_path = l[0]
                if not os.path.exists(config_path):
                    print("Config file not found.")
                    raise ValueError
            else:
                raise ValueError
    except ValueError:
        print(
            "Usage: \n"
            "    python natter.py [-v] [-t] [SRC_IP] SRC_PORT\n"
            "    python natter.py --check-nat [SRC_IP] SRC_PORT\n"
            "    python natter.py --check-nat\n"
            "    python natter.py -c config_file\n"
        )
        return
    
    if check_nat:
        print_nat(src_host, src_port)
        return
    
    http_test_server = None
    if not use_config:
        # TCP single port punching
        log_level = Logger.DEBUG if verbose else Logger.INFO
        natter = Natter("www.qq.com", interval=10, logger=Logger(log_level))
        natter.add_tcp_open_port((src_host, src_port))
        if test_http:
            http_test_server = HttpTestServer((src_host, src_port), logger=natter.logger)
            http_test_server.start()
    else:
        natter = Natter.from_config(config_path)

    try:
        natter.run()
    except KeyboardInterrupt:
        if http_test_server:
            http_test_server.stop()
        natter.logger.info("Exiting...")
        natter.close()
        os._exit(0)

if __name__ == '__main__':
    main()
