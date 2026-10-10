from backend.app.scanners.nmap_scanner import scan_target


result = scan_target("127.0.0.1")

print("\n=== CyberAgis Scan Result ===")

print(result)