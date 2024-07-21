import re
import socket
import typing


SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900


def generate_ssdp_response(headers: typing.Dict):
    response = "HTTP/1.1 200 OK\r\n"
    for key, value in headers.items():
        response += f"{key.upper()}: {value}\r\n"
    response += "\r\n"
    return response


def parse_ssdp_response(response: bytes):
    lines = response.decode('utf8').strip().split('\r\n')
    headers = {}

    for line in lines:
        match = re.match(r'([A-Z]+): (.*)', line)
        if match:
            key = match.group(1).lower()
            value = match.group(2).lower()
            headers[key] = value

    return headers


def discover_ssdp_devices(mx=5, man="ssdp:discover", st="ssdp:all", ssdp_filter=''):
    ssdp_request = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {0}:{1}'.format(SSDP_ADDR, SSDP_PORT),
        f'MAN: "{man}"',
        'MX: {0}'.format(mx),
        f'ST: {st}',
        '',
        ''
    ]).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    responses = []

    try:
        sock.sendto(ssdp_request, (SSDP_ADDR, SSDP_PORT))

        devices = {}

        while True:
            try:
                responses.append(sock.recvfrom(1024))
            except socket.timeout:
                break

        for data, addr in responses:
            if data:
                parsed_data = parse_ssdp_response(data)
                st = parsed_data.get('st')
                if st:
                    devices[addr[0]] = devices.get(addr[0], {})
                    devices[addr[0]][st] = parsed_data

        devices = {k: v for k, v in devices.items() if ssdp_filter in str(v).lower()}
    finally:
        sock.close()
    return devices

if __name__ == '__main__':
    import json
    print(json.dumps(discover_ssdp_devices(ssdp_filter='roku'), indent=True))
