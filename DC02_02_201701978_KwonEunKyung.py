import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header=struct.unpack("!6c6c2s", data)
    ether_src=convert_ethernet_address(ethernet_header[0:6])
    ether_dest=convert_ethernet_address(ethernet_header[6:12])
    ip_header="0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address: ", ether_src)
    print("dest_mac_address: ", ether_dest)
    print("ip_version",ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr=":".join(ethernet_addr)
    return ethernet_addr
         
def parsing_ip_header(data):
    ipv4_header = struct.unpack("!B B H H H B B H 4s 4s", data[0][14:34])
    ip_version = (ipv4_header[0]&0xF0)>>4
    ip_length = (ipv4_header[0]&0x0F)
    dsc = (ipv4_header[1]&0xFC)>>2
    ecn = (ipv4_header[1]&0x03)
    tl = (ipv4_header[2]&0xe000)>>13
    identification = (ipv4_header[3])
    flags = (ipv4_header[4])
    re_bit = (ipv4_header[4]&0x8000)>>15
    not_fr = (ipv4_header[4]&0x4000)>>14
    fr = (ipv4_header[4]&0x2000)>>13
    fr_off = (ipv4_header[4]&0x1FFF)
    tol = (ipv4_header[5])
    protocol = (ipv4_header[6])
    hc = (ipv4_header[7])
    sia = socket.inet_ntoa(ipv4_header[8])
    dia = socket.inet_ntoa(ipv4_header[9])

    print("========ip_header========")
    print("ip_version: ", ip_version)
    print("ip_length: ", ip_length)
    print("differentiated_service_codepoint: ", dsc)
    print("explicit_congestion_notification: ", ecn)
    print("total_length: ", tl)
    print("identification: ", identification)
    print("flags: ", flags)
    print(">>>reseved_bit: ", re_bit)
    print(">>>not_fragment: ", not_fr)
    print(">>>fragments: ", fr)
    print(">>>fragments_offset: ", fr_off)
    print("Time to live: ", tol)
    print("protocol: ",protocol)
    print("header checksum: ", hc)
    print("source_ip_address: ", sia)
    print("dest_ip_adderss: ", dia)

    if protocol==6:
        parsing_tcp_header(data[0][34:54])
    elif protocol ==17:
        parsing_udp_header(data[0][34:42])

def  parsing_tcp_header(data):
    tcp_header =  struct.unpack("!H H I I B B H H H", data)
    src_port = (tcp_header[0])
    dec_port = (tcp_header[1])
    seq_num = (tcp_header[2])
    ack_num = (tcp_header[3])
    header_len = (tcp_header[5]&0xF0)>>4
    flags = (tcp_header[5])
    reserved = (tcp_header[5]&0xe00)>>9
    nonce = (tcp_header[5]&0x100)>>8
    cwr = (tcp_header[5]&0x80)>>7
    urgent = (tcp_header[5]&0x20)>>5
    ack = (tcp_header[5]&0x00)>>4
    push = (tcp_header[5]&0x8)>>3
    reset = (tcp_header[5]&0x4)>>2
    syn = (tcp_header[5]&0x2)>>1
    fin = (tcp_header[5]&0x1)
    window_size_value = tcp_header[6]
    checksum = tcp_header[7]
    urgent_pointer = tcp_header[8]
    print("=======tcp_header========")
    print("src_port: ", src_port)
    print("dec_port: ",dec_port)
    print("seq_num: ", seq_num)
    print("ack_num: ", ack_num)
    print("header_len: ", header_len)
    print("flags: ", flags)
    print(">>>reserved: ",reserved)
    print(">>>nonce: ", nonce)
    print(">>>cwr: ", cwr)
    print(">>>urgent: ", urgent)
    print(">>>ack: ", ack)
    print(">>>push: ", push)
    print(">>>reset: ", reset)
    print(">>>syn: ", syn)
    print(">>>fin: ", fin)
    print("window_size_value: ",window_size_value)
    print("checksum: ",checksum)
    print("urgent_pointer: ",urgent_pointer)

def parsing_udp_header(data):
    udp_header = struct.unpack("!H H H H",data)
    src_port = udp_header[0]
    dst_port = udp_header[1]
    leng = udp_header[2]
    header_checksum = udp_header[3]
    print("=======udp_header=======")
    print("src_port: ",src_port)
    print("dst_port: ",dst_port)
    print("leng: ", leng)
    print("header checksum: ", header_checksum)

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

print("<<<<<<<< Packet Capture Start >>>>>>>")
while True:
        data =  recv_socket.recvfrom(20000)
        parsing_ethernet_header(data[0][0:14])
        parsing_ip_header(data)
