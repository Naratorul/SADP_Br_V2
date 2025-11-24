import socket, struct, json, threading, ipaddress, queue, time, select, sys, os

SADP_PORT = 37020
SADP_BCAST = "255.255.255.255"
SADP_DISC = bytes.fromhex("fefefefe000000000f00000000000000")
SSDP_GROUP = ("239.255.255.250", 1900)
SSDP_DISC = b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\n\r\n"
QNAP_DISC = b"QDISCOVERY"
MDNS_GROUP = ("224.0.0.251", 5353)
PORTS = [80, 443, 445, 139, 554, 8000, 8080, 5000, 5001, 1319, 1320, 8899, 9000]

results = {"sadp": [], "subnet": [], "nas": [], "meta": {"start": time.time()}}

def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_netmask_for_ip(ip):
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        max_if = 128
        names = array = struct.pack('256s', b'')
        for i in range(max_if):
            pass
    except:
        pass
    try:
        if os.name != "nt":
            import fcntl, array
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifs = array.array('B', b'\0' * 4096)
            bytelen = struct.calcsize('iL')
            SIOCGIFCONF = 0x8912
            res = fcntl.ioctl(sock.fileno(), SIOCGIFCONF, struct.pack('iL', 4096, ifs.buffer_info()[0]))
            outbytes = struct.unpack('iL', res)[0]
            namestr = ifs.tobytes()[:outbytes]
            for i in range(0, outbytes, 40):
                name = namestr[i:i+16].split(b'\0', 1)[0].decode()
                addr = socket.inet_ntoa(namestr[i+20:i+24])
                if addr == ip:
                    SIOCGIFNETMASK = 0x891b
                    ifreq = struct.pack('256s', name.encode())
                    netm = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, ifreq)[20:24]
                    return socket.inet_ntoa(netm)
    except:
        pass
    return "255.255.255.0"

def ip_network_from_local():
    ip = get_primary_ip()
    nm = get_netmask_for_ip(ip)
    try:
        net = ipaddress.ip_network(f"{ip}/{nm}", strict=False)
    except:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(net)

def parse_sadp_response(data, addr):
    h = data.hex()
    try:
        ip_hex = h[72:80]
        ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(0, 8, 2))
        mac_hex = h[80:92]
        mac = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
        model_len = int(h[96:98], 16)
        model_start = 98
        model_end = model_start + model_len * 2
        model = bytes.fromhex(h[model_start:model_end]).decode(errors="ignore")
        serial_len = int(h[model_end:model_end+2], 16)
        serial_start = model_end + 2
        serial_end = serial_start + serial_len * 2
        serial = bytes.fromhex(h[serial_start:serial_end]).decode(errors="ignore")
        active_flag = h[50:52]
        active = active_flag != "00"
        return {"ip": ip, "mac": mac, "model": model, "serial": serial, "active": active, "source": addr[0], "raw": h}
    except:
        return {"source": addr[0], "raw": data.hex(), "parse_error": True}

def sadp_discover(timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(SADP_DISC, (SADP_BCAST, SADP_PORT))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                results["sadp"].append(parse_sadp_response(data, addr))
            except socket.timeout:
                break
            except:
                break
    finally:
        sock.close()

def port_scan_ip(ip, ports=PORTS, timeout=0.25):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
        except:
            pass
        finally:
            try:
                s.close()
            except:
                pass
    return open_ports

def subnet_worker(q, lock):
    while True:
        try:
            ip = q.get_nowait()
        except:
            break
        ops = port_scan_ip(ip)
        if ops:
            entry = {"ip": ip, "ports": ops}
            with lock:
                results["subnet"].append(entry)
        q.task_done()

def subnet_scan(subnet, workers=120):
    net = ipaddress.ip_network(subnet, strict=False)
    q = queue.Queue()
    for ip in net.hosts():
        q.put(str(ip))
    lock = threading.Lock()
    threads = []
    for _ in range(workers):
        t = threading.Thread(target=subnet_worker, args=(q, lock))
        t.daemon = True
        t.start()
        threads.append(t)
    q.join()
    for t in threads:
        t.join()

def ssdp_discover(timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(SSDP_DISC, SSDP_GROUP)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                txt = data.decode(errors="ignore")
                lower = txt.lower()
                if any(k in lower for k in ("synology", "nas", "dlna", "upnp", "server:")):
                    results["nas"].append({"type": "ssdp", "addr": addr[0], "info": txt})
            except:
                break
    finally:
        sock.close()

def qnap_discover(timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(timeout)
        s.sendto(QNAP_DISC, (SADP_BCAST, 1319))
        end = time.time() + timeout
        while time.time() < end:
            try:
                d, a = s.recvfrom(2048)
                results["nas"].append({"type": "qnap", "addr": a[0], "raw": d.hex()})
            except:
                break
    finally:
        s.close()

def mdns_discover(timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", 5353))
        except:
            s.bind((get_primary_ip(), 0))
        group = socket.inet_aton(MDNS_GROUP[0])
        mreq = group + socket.inet_aton("0.0.0.0")
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except:
            pass
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                b"\x09_locality\x04_local\x05local\x00\x00\x0c\x00\x01"
        s.settimeout(timeout)
        try:
            s.sendto(query, MDNS_GROUP)
        except:
            pass
        end = time.time() + timeout
        while time.time() < end:
            try:
                d, a = s.recvfrom(4096)
                results["nas"].append({"type": "mdns", "addr": a[0], "raw": d.hex()})
            except:
                break
    finally:
        s.close()

def netbios_probe(timeout=1):
    pkt = b"\x00\x00" + b"\x01\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x20"
    try:
        name = "*               "
        enc = b""
        for c in name:
            v = ord(c) if isinstance(c, str) else c
            enc += bytes([((v >> 4) & 0x0F) + ord('A'), (v & 0x0F) + ord('A')])
        pkt = b"\x00\x00" + b"\x00\x00" + b"\x00\x01" + b"\x00\x00" + enc + b"\x00\x20\x00\x01"
    except:
        pkt = b"\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    net = ipaddress.ip_network(ip_network_from_local(), strict=False)
    for host in list(net.hosts())[:254]:
        try:
            s.sendto(pkt, (str(host), 137))
            d, a = s.recvfrom(1024)
            results["nas"].append({"type": "netbios", "addr": a[0], "raw": d.hex()})
        except:
            pass
    try:
        s.close()
    except:
        pass

def run_all():
    net = ip_network_from_local()
    t1 = threading.Thread(target=sadp_discover, args=(2,))
    t2 = threading.Thread(target=lambda: subnet_scan(net, 120))
    t3 = threading.Thread(target=ssdp_discover, args=(2,))
    t4 = threading.Thread(target=qnap_discover, args=(2,))
    t5 = threading.Thread(target=mdns_discover, args=(2,))
    t6 = threading.Thread(target=netbios_probe, args=(1,))
    for t in (t1, t2, t3, t4, t5, t6):
        t.daemon = True
        t.start()
    for t in (t1, t2, t3, t4, t5, t6):
        t.join()
    results["meta"]["net"] = net
    results["meta"]["end"] = time.time()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_all()
