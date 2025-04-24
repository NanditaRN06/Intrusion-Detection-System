import socket
import struct
import threading
import time
import os
from ssl_utils import create_ssl_context

ATTACK_SIGNATURES = [b'evil_code', b'\xde\xad\xbe\xef']
LOG_FILE = "intrusion_log.txt"
ADMIN_PASSWORD = "sehnrn6559" 

def log_intrusion(msg):
    with open(LOG_FILE, "a") as log: log.write(msg + "\n")

def parse_packet_data(data, addr):
    return {
        "src_ip": addr[0],
        "dst_ip": "server",
        "protocol": "TCP",
        "payload": data
    }

def detect_intrusion(packet_info, control_sockets):
    if packet_info:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S') + f".{int(time.time() * 1000) % 1000}"
        print(f"[+] {timestamp} - Packet from {packet_info['src_ip']} to {packet_info['dst_ip']}")

        for signature in ATTACK_SIGNATURES:
            if signature in packet_info["payload"]:
                alert_msg = f"\033[92m[!] {timestamp} - Potential Attack Detected from {packet_info['src_ip']}\033[0m"
                plain_msg = f"[!] {timestamp} - Potential Attack Detected from {packet_info['src_ip']}"
                print(alert_msg)
                log_intrusion(plain_msg)
                for cs in control_sockets:
                    try:
                        cs.sendall(f"ALERT: Intrusion from {packet_info['src_ip']}".encode())
                    except:
                        pass
                return

def client_data_handler(conn, addr, control_sockets):
    print(f"[*] Client connected from {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            pkt_info = parse_packet_data(data, addr)
            detect_intrusion(pkt_info, control_sockets)
    except:
        pass
    finally:
        print(f"[!] Client {addr} disconnected.")
        conn.close()

def data_server(control_sockets):
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    data_socket.bind(("0.0.0.0", 9999))
    data_socket.listen()
    print("[*] Data Server started. Waiting for client connections...")
    try:
        while True:
            conn, addr = data_socket.accept()
            threading.Thread(target=client_data_handler, args=(conn, addr, control_sockets), daemon=True).start()
    except Exception as e:
        print(f"[!] Data server error: {e}")
    finally:
        data_socket.close()
        print("[*] Data server socket closed.")

def control_channel_handler(client_conn, addr, control_sockets):
    try:
    	client_conn.sendall(b"Enter admin password: ")
    	password = client_conn.recv(1024).decode().strip()
    	if(password != ADMIN_PASSWORD):
    		print(f"[!] Incorrect password attempt from {addr}")
    		client_conn.sendall(b"DENIED")
    		client_conn.close()
    		return
    	print(f"[+] Admin connected from {addr}")
    	client_conn.sendall(b"GRANTED")
    	control_sockets.append(client_conn)
    except Exception as e:
    	print(f"[!] Error in control handler: {e}")
    	client_conn.close()

def start_server():
    context = create_ssl_context()
    control_sockets = []

    control_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control_server.bind(("0.0.0.0", 8443))
    control_server.listen()

    threading.Thread(target=data_server, args=(control_sockets,), daemon=True).start()
    print("[*] IDS Server started. Waiting for admin connections...")

    try:
        while True:
            conn, addr = control_server.accept()
            ssl_conn = context.wrap_socket(conn, server_side=True)
            threading.Thread(target=control_channel_handler, args=(ssl_conn, addr, control_sockets), daemon=True).start()
    except KeyboardInterrupt: print("\n[!] Server shutdown requested.")
    except Exception as e: print(f"[!] Server error: {e}")
    finally:
        control_server.close()
        print("[*] Server socket closed.")
        log_intrusion("________________________________________________________________________________________")

if __name__ == "__main__":
    try: start_server()
    except Exception as e: print(f"[!] Unexpected server termination: {e}")
