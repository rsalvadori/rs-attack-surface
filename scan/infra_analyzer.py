import socket
import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False


# =========================
# IPs (MELHORADO)
# =========================
def get_ips(domain):
    ips = set()

    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, "A")
            for r in answers:
                ips.add(str(r))
        except:
            pass

    try:
        ip = socket.gethostbyname(domain)
        ips.add(ip)
    except:
        pass

    return list(ips)


# =========================
# DNS
# =========================
def get_dns_records(domain):
    records = {
        "A": [],
        "MX": [],
        "NS": []
    }

    if not DNS_AVAILABLE:
        return records

    try:
        records["A"] = [str(r) for r in dns.resolver.resolve(domain, "A")]
    except:
        pass

    try:
        records["MX"] = [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
    except:
        pass

    try:
        records["NS"] = [str(r) for r in dns.resolver.resolve(domain, "NS")]
    except:
        pass

    return records


# =========================
# PORT SCAN LEVE
# =========================
def detect_services(ip):
    services = []

    ports = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        21: "FTP",
        25: "SMTP"
    }

    for port, name in ports.items():
        try:
            sock = socket.create_connection((ip, port), timeout=1)
            sock.close()
            services.append(name)
        except:
            continue

    return services


# =========================
# GEO + ISP
# =========================
def get_geo(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)

        if response.status_code == 200:
            data = response.json()

            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org")
            }
    except:
        pass

    return None


# =========================
# REVERSE DNS (NOVO)
# =========================
def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


# =========================
# CORE
# =========================
def analyze_infrastructure(domain):

    result = {
        "ips": [],
        "dns": {},
        "services": [],
        "geo": {},
        "hostnames": {}  # 🔥 NOVO
    }

    ips = get_ips(domain)
    result["ips"] = ips

    result["dns"] = get_dns_records(domain)

    all_services = set()

    for ip in ips:
        # serviços
        services = detect_services(ip)
        all_services.update(services)

        # geo
        geo = get_geo(ip)
        if geo:
            result["geo"][ip] = geo

        # reverse dns
        hostname = get_reverse_dns(ip)
        if hostname:
            result["hostnames"][ip] = hostname

    result["services"] = list(all_services)

    return result