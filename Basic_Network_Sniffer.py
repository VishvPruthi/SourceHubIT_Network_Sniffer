import socket
import struct
import textwrap
from datetime import datetime

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

# Create raw socket
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
log_file = open("packet_log.txt", "a")

while True:
    raw_data, addr = conn.recvfrom(65536)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    if eth_proto == 8:  # IPv4
        ttl, proto, src_ip, target_ip, data = ipv4_packet(data)
        info = f"\n[{timestamp}] IPv4 Packet: {src_ip} → {target_ip}, Protocol: {proto}\n"
        print(info)
        log_file.write(info)