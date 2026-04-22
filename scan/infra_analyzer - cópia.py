import socket
import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def get_dns_records(domain):
    records = {
        "A": [],
        "MX": [],
        "NS": []
    }

    if not DNS_AVAILABLE:
        return records

    try:
        answers = dns.resolver.resolve(domain, "A")
        records["A"] = [str(r) for r in answers]
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, "MX")
        records["MX"] = [str(r.exchange) for r in answers]
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, "NS")
        records["NS"] = [str(r) for r in answers]
    except:
        pass

    return records


def detect_services(domain):
    services = []

    ports = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        21: "FTP",
        25: "SMTP"
    }

    ip = get_ip(domain)

    if not ip:
        return services

    for port, name in ports.items():
        try:
            sock = socket.create_connection((ip, port), timeout=2)
            sock.close()
            services.append(name)
        except:
            continue

    return services


def get_geo(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)

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


def analyze_infrastructure(domain):

    result = {
        "ips": [],
        "dns": {},
        "services": [],
        "geo": {}
    }

    ip = get_ip(domain)

    if ip:
        result["ips"].append(ip)

        geo = get_geo(ip)
        if geo:
            result["geo"][ip] = geo

    result["dns"] = get_dns_records(domain)

    result["services"] = detect_services(domain)

    return result