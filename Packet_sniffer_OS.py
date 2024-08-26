import socket
import struct
import textwrap 

print ('Tool intialized')

tab = lambda num: "\t"*num
DATA_TAB_3 = "\t" * 3
TAB_1 = "\t" * 1

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Loop Packet sniffer
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr= conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print ('Ethernet Frame:')
        print(tab(1) + 'Destination: {}, Source:{}, Protocol:{}'. format(dest_mac, src_mac, eth_proto))
        
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)  # Changed header_lenght to header_length
            print(tab(1) + 'IPV4 packet:')
            print(tab(2) + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(tab(3) + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(tab(1) + 'ICMP Packet:')
                print(tab(2) + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(tab(3) + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)  # Added tcp_segment function and changed flag_pst to flag_rst
                print(tab(1) + 'TCP Segment:')
                print(tab(2) + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(tab(2) + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(tab(3) + 'Flags:')
                print(tab(4) + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))  # Changed flag_pst to flag_rst
                print(tab(5) + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # Other protocols
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

        else:
            print('Unsupported protocol')


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

 # Return properly formatted MAC adress (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()
    
# Unpacks ipv4 data
def ipv4_packet(data):
	version_header_length= data [0]
	version = version_header_length >> 4
	(version_header_length & 15) * 4
	header_length = (version_header_length & 15) * 4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
	
#Return properly formatted IPV4 adress
def ipv4 (addr):
	return '.'.join(map(str, addr))

#Unpacks ICMP packet
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[:4]

#Unpacks TCP packet
def tcp_segment(data):
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >>12 ) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:] 


  
    
main()
 


