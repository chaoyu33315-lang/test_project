import socket

ip = "51.83.131.156"
ports = [21, 22, 25, 53, 80, 443, 3306, 8080, 8443]

print(f"[*] Scanning common ports on {ip}...")
for port in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port}: OPEN")
            try:
                s.settimeout(3)
                if port == 22:
                    banner = s.recv(1024)
                    if banner:
                        print(f"    SSH Banner: {banner.decode(errors='ignore').strip()}")
                elif port in (80, 443):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    response = s.recv(2048)
                    print(f"    HTTP Response snippet:\n{response.decode(errors='ignore')[:300]}")
            except Exception as ex:
                print(f"    Error reading banner/response: {ex}")
        s.close()
    except Exception as e:
        pass
print("[*] Scan finished.")
