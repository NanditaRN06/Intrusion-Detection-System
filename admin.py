import socket
import ssl
import hashlib
import os
from ssl_utils import create_client_ssl_context, ssl
import sys
import tty
import termios

CONTROL_SERVER = '192.168.50.2' # server IP
CONTROL_PORT = 8443

def get_password(prompt="Enter your password: "):
    print(prompt, end='', flush=True)
    password = ''
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ('\r', '\n'):
                print()
                break
            elif ch == '\x7f': 
                if len(password) > 0:
                    password = password[:-1]
                    print('\b \b', end='', flush=True)
            else:
                password += ch
                print('*', end='', flush=True)
    finally: termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password

def admin():
    try: context = create_client_ssl_context()
    except FileNotFoundError:
        print("[!] ERROR: SSL certification not found. Cannot verify server identity.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssl_sock = context.wrap_socket(sock, server_hostname=CONTROL_SERVER)
        ssl_sock.connect((CONTROL_SERVER, CONTROL_PORT))
        
        prompt = ssl_sock.recv(1024).decode()
        print(prompt, end='')
        password = get_password()
        ssl_sock.sendall(password.encode())
        response = ssl_sock.recv(1024).decode()
        if response != "GRANTED":
        	print("[!] Access denied.")
        	ssl_sock.close()
        	return
        	
        print("[*] Connected to IDS Control Server. Listening for alerts...")

        try:
            while True:
                alert = ssl_sock.recv(1024).decode()
                if alert: print(f"[ALERT] {alert}")
        except KeyboardInterrupt: print("[!] Admin disconnecting...")
        finally: ssl_sock.close()

    except ssl.SSLError as e:
        print(f"[!] SSL error: {e}")
        print("[!] Invalid authorization.")
    except ConnectionRefusedError:
        print("[!] Could not connect to the IDS Control Server. Is the server running?")
    except Exception as e: print(f"[!] Unexpected error: {e}")
    finally: sock.close()

def check_cert_fingerprint(cert_path, expected_fp):
    if not os.path.exists(cert_path):
        print(f"[!] ERROR: Not certified...")
        return False

    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        if not hasattr(hashlib, 'sha256'):
            print("[!] Certificate not supported.")
            return False

        actual_fp = hashlib.sha256(cert_data).hexdigest().upper()
        expected_fp = expected_fp.replace(":", "").upper()

        if actual_fp == expected_fp:
            print("[*] Certificate Verified..")
            return True
        else:
            print("[!] WARNING: Wrong Certificate.")
            return False

    except Exception as e:
        print(f"[!] Error checking fingerprint: {e}")
        return False

if __name__ == "__main__":
    if not check_cert_fingerprint("server.crt", "123456ABCDEF..."):
        print("[!] Not authorised. Aborting...")
        exit(1)
    admin()

