import subprocess
import xml.etree.ElementTree as ET


def run_nmap(target: str):
    command = [
        "nmap",
        "-sV",
        "-oX",
        "-",
        target
    ]

    print(f"[*] Starting Nmap scan on {target}...")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            print("[!] Nmap scan failed")
            print(result.stderr)
            return None

        print("[+] Nmap scan completed")

        return result.stdout

    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out")
        return None

    except FileNotFoundError:
        print("[!] Nmap executable was not found")
        return None


def parse_nmap_xml(xml_data: str):
    root = ET.fromstring(xml_data)

    host = root.find("host")

    if host is None:
        return None

    address = host.find("address")

    target = None

    if address is not None:
        target = address.get("addr")

    status_element = host.find("status")

    status = None

    if status_element is not None:
        status = status_element.get("state")

    hostname_element = host.find("hostnames/hostname")

    hostname = None

    if hostname_element is not None:
        hostname = hostname_element.get("name")

    ports = []

    ports_element = host.find("ports")

    if ports_element is not None:

        for port in ports_element.findall("port"):

            protocol = port.get("protocol")
            port_number = port.get("portid")

            state_element = port.find("state")
            service_element = port.find("service")

            state = None
            service = None
            product = None
            version = None

            if state_element is not None:
                state = state_element.get("state")

            if service_element is not None:
                service = service_element.get("name")
                product = service_element.get("product")
                version = service_element.get("version")

            ports.append({
                "port": int(port_number),
                "protocol": protocol,
                "state": state,
                "service": service,
                "product": product,
                "version": version
            })

    return {
        "target": target,
        "hostname": hostname,
        "status": status,
        "ports": ports
    }


def scan_target(target: str):
    xml_data = run_nmap(target)

    if xml_data is None:
        return None

    return parse_nmap_xml(xml_data)