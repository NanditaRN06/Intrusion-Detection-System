# 🛡️ Intrusion Detection System (IDS)

A custom-built Intrusion Detection System (IDS) using raw sockets and SSL encryption, developed in Python. This project is designed to monitor and detect potentially malicious network traffic across a client-server architecture, providing real-time alerts to an admin dashboard.

## 📦 Project Structure

```
.
├── client.py        # Sends data (regular or malicious) to server
├── server.py        # Analyzes incoming packets, detects intrusions
├── admin.py         # Receives and displays alerts from the server
├── ssl_utils.py     # Handles SSL socket creation and certificate management
├── README.md        # Project documentation
```

## 🔐 Features

- ⚙️ **Raw Socket Communication**: Low-level packet handling without third-party libraries.
- 🔄 **Separate Control and Data Channels**: Ensures clean, structured communication.
- 🧠 **Intrusion Detection**: Recognizes predefined malicious packet patterns.
- 📡 **Multi-client, Multi-server Support**: Scalable design supporting simultaneous interactions.
- 🔒 **SSL Encryption**: Secures communication between client, server, and admin.
- ✅ **Graceful Termination**: Clean shutdown without bind errors or socket reuse issues.
- 🌐 **Real-time Admin Alerts**: Server alerts admin terminal when threats are detected.
- 🖥️ **Color-coded CLI Output**: Green-highlighted detection messages for better visibility.

## ⚙️ Setup & Usage

### Prerequisites

- Python 3.x
- Linux environment (tested on Ubuntu VMs)
- OpenSSL for generating certificates

### Certificate Generation

Generate certificates for SSL communication:

```bash
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
```

After generation, find out the fingerprint value of your certificate and put it in ###admin.py

### 1. Start the Admin

```bash
python3 admin.py
```

### 2. Start the Server

```bash
python3 server.py
```

### 3. Start a Client

```bash
python3 client.py
```

## 🧪 Test Scenarios

- **Normal Client**: Sends well-formed data to the server.
- **Malicious Client**: Sends predefined attack signatures (e.g., `DROP TABLE`, `sudo rm -rf /`).
- **Disconnected Client**: Verifies server/admin behavior on dropped connections.
- **Multiple Clients**: Validates concurrent session handling.
- **SSL Handshake Failure**: Tests error handling for SSL misconfigurations.

## 🔍 How It Works

- `client.py`: Sends packets (normal/malicious) to the server's data channel.
- `server.py`: Inspects packet contents, identifies threats, and alerts admin via control channel.
- `admin.py`: Displays intrusion alerts in real-time with color-coded output.
- `ssl_utils.py`: Ensures secure communication using SSL-wrapped sockets.

## 🧠 Detection Logic

- Simple pattern matching on suspicious keywords.
- Can be extended with regex or ML-based classifiers for smarter detection.

## 📌 Known Limitations

- Static signature-based detection.
- No logging or GUI dashboard yet.
- Tested only on Linux with Python sockets.

## 🤝 Contributors

- Najmus Seher 
- Nandita R Nadig

## 📜 License

This project is licensed under the MIT License.
