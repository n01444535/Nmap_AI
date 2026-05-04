# EN: Find the local machine address before scanning.
# VI: Tìm địa chỉ của máy này trước khi quét.

import socket

# EN: Find this computer IP address on the network.
# VI: Tìm địa chỉ IP của máy này trong mạng.
def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    finally:
        sock.close()
    return ip
