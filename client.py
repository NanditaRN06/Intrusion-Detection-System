import socket
import time
from ssl_utils import create_client_ssl_context

DATA_SERVER = '192.168.50.2'  # server IP
DATA_PORT = 9999

def send_packet(data_sock, data):
    data_sock.sendall(data)

def client():
    try:
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.connect((DATA_SERVER, DATA_PORT))

        td = [2, 7, 13, 20]
        start_time = time.time()
        last_packet_time = time.time()
        index = 0
        packet_count = 0

        while packet_count < 30:
            current_time = time.time()
            if current_time - last_packet_time >= 3:
                if current_time - start_time >= td[index]:
                    send_packet(data_sock, b'evil_code')
                    index = (index + 1) % len(td)
                    start_time = time.time()
                else:
                    send_packet(data_sock, b'normal_data')
                last_packet_time = time.time()
                packet_count += 1
    except ConnectionRefusedError:
        print("[!] Could not connect to the IDS Data Server. Is the server running?")
    except KeyboardInterrupt:
        print("[!] Client interrupted by user.")
    finally:
        data_sock.close()
        print("[*] Client socket closed.")

if __name__ == "__main__":
    client()
