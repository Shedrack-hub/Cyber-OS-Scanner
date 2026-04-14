import socket

PORTS = [21, 22, 23, 25, 53, 80, 110, 443]


def detect_ip_type(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return socket.AF_INET  # IPv4
    except:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return socket.AF_INET6  # IPv6
        except:
            return None


def scan_single_ip(ip):
    results = []

    ip_type = detect_ip_type(ip)

    if ip_type is None:
        return [{
            "ip": ip,
            "port": "-",
            "service": "Invalid IP",
            "risk": "High",
            "description": "Invalid IP format",
            "ip_type": "Unknown",
             "device": "Unknown"
        }]

    for port in PORTS:
        s = socket.socket(ip_type, socket.SOCK_STREAM)
        s.settimeout(0.5)

        try:
            status = s.connect_ex((ip, port))

            if status == 0:
                results.append({
                    "ip": ip,
                    "port": port,
                    "service": get_service(port),
                    "risk": get_risk(port),
                    "description": get_description(port),
                    "ip_type": "IPv4" if ip_type == socket.AF_INET else "IPv6",
                    "device": "Unknown",
                })

        except Exception:
            pass
        finally:
            s.close()

    if not results:
        return [{
            "ip": ip,
            "port": "-",
            "service": "SECURE HOST",
            "risk": "Low",
            "description": "No exposed services. Target is hardened or behind firewall.",
            "ip_type": "IPv4" if ip_type == socket.AF_INET else "IPv6",
            "device": "Hardened / Firewall Protected System"
        }]
    
    if results:
        device = detect_device(results)

        for r in results:
            r["device"] = device

    return results


def scan_range(base_ip, start, end):
    results = []

    for i in range(start, end + 1):
        ip = f"{base_ip}.{i}"
        results.extend(scan_single_ip(ip))

    return results


# ---------------- HELPERS ----------------

def get_service(port):
    return {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        443: "HTTPS"
    }.get(port, "Unknown")


def get_risk(port):
    if port == 23:
        return "High"
    elif port in [21, 25, 110]:
        return "Medium"
    else:
        return "Low"


def get_description(port):
    return {
        21: "File Transfer Service",
        22: "Secure Remote Login",
        23: "Insecure Remote Access",
        25: "Mail Transfer",
        53: "Domain Resolution",
        80: "Web Traffic (HTTP)",
        110: "Email Retrieval",
        443: "Secure Web (HTTPS)"
    }.get(port, "Service detected")

def detect_device(open_ports):
    ports = [p["port"] for p in open_ports if isinstance(p["port"], int)]

    if 80 in ports and 443 in ports and 53 in ports:
        return "Router / Network Device"

    if 80 in ports or 443 in ports:
        return "Web Server"

    if 22 in ports:
        return "Linux/Unix Machine (SSH)"

    if 23 in ports:
        return "Legacy Device (Telnet - insecure)"

    if 25 in ports:
        return "Mail Server"

    return "Unknown / Secured Device"