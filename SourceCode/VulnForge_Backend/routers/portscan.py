from fastapi import APIRouter
import subprocess
import xml.etree.ElementTree as ET

router = APIRouter()

def parse_nmap_xml(xml_output):
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            for port in host.findall('./ports/port'):
                state = port.find('state')
                service = port.find('service')
                if state is not None and state.get('state') == 'open':
                    ports.append({
                        "port": port.get('portid'),
                        "protocol": port.get('protocol'),
                        "state": state.get('state'),
                        "service": service.get('name') if service is not None else 'unknown',
                        "version": service.get('product', '') + ' ' + service.get('version', '') if service is not None else ''
                    })
    except Exception as e:
        pass
    return ports

@router.get("/")
def port_scan(target: str, scan_type: str = "basic"):
    try:
        if scan_type == "basic":
            cmd = ["nmap", "-T4", "-F", "--max-retries", "1", "--open", "-oX", "-", target]
        elif scan_type == "full":
            cmd = ["nmap", "-T4", "-p-", "--max-retries", "1", "--min-rate", "500", "--open", "-oX", "-", target]
        elif scan_type == "service":
            # Removed slow -sC script scan, added --version-light for fast service fingerprinting
            cmd = ["nmap", "-T4", "-sV", "--version-light", "--max-retries", "1", "--open", "-oX", "-", target]
        elif scan_type == "udp":
            # UDP scanning is naturally very slow; limiting to top 100 (-F)
            cmd = ["sudo", "nmap", "-sU", "-T4", "-F", "--max-retries", "1", "--open", "-oX", "-", target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800
        )

        ports = parse_nmap_xml(result.stdout)

        return {
            "target": target,
            "scan_type": scan_type,
            "status": "success",
            "total_open_ports": len(ports),
            "ports": ports
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
