# EN: Provide small fake scan data when real Nmap data is missing.
# VI: Cho dữ liệu mẫu khi chưa có dữ liệu Nmap thật.

# EN: Return small sample hosts for fallback mode.
# VI: Trả về vài máy mẫu khi cần dùng tạm.
def get_sample_records(local_ip):
    return [
        {
            "ip": local_ip,
            "hostname": "sample-safe-host",
            "open_ports": [
                {
                    "protocol": "tcp",
                    "port": 22,
                    "service": "ssh",
                    "product": "",
                    "version": ""
                },
                {
                    "protocol": "tcp",
                    "port": 443,
                    "service": "https",
                    "product": "",
                    "version": ""
                }
            ]
        },
        {
            "ip": "127.0.0.1",
            "hostname": "sample-risky-host",
            "open_ports": [
                {
                    "protocol": "tcp",
                    "port": 21,
                    "service": "ftp",
                    "product": "",
                    "version": ""
                },
                {
                    "protocol": "tcp",
                    "port": 23,
                    "service": "telnet",
                    "product": "",
                    "version": ""
                },
                {
                    "protocol": "tcp",
                    "port": 445,
                    "service": "microsoft-ds",
                    "product": "",
                    "version": ""
                },
                {
                    "protocol": "tcp",
                    "port": 3389,
                    "service": "ms-wbt-server",
                    "product": "",
                    "version": ""
                }
            ]
        }
    ]
