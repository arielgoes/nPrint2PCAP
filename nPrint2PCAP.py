import struct
import pandas as pd
import random
import socket


# PCAP Global Header
def create_pcap_header():
    return struct.pack(
        '<IHHIIII', 
        0xA1B2C3D4,  # Magic Number
        2,            # Version Major
        4,            # Version Minor
        0,            # Thiszone
        0,            # Sigfigs
        65535,        # Snaplen
        1             # Network (Ethernet)
    )

# PCAP Packet Header
def create_pcap_packet_header(timestamp, length):
    seconds, microseconds = divmod(timestamp, 1)
    microseconds = int(microseconds * 1e6)
    return struct.pack(
        '<IIII', 
        int(seconds),          # Timestamp seconds
        int(microseconds),     # Timestamp microseconds
        length,                # Captured length
        length                 # Original length
    )

def create_ethernet_header():
    # Random MAC addresses
    src_mac = bytes(random.randint(0, 255) for _ in range(6))
    dst_mac = bytes(random.randint(0, 255) for _ in range(6))
    ether_type = struct.pack('>H', 0x0800)  # EtherType for IPv4

    return dst_mac + src_mac + ether_type


def ipv4_checksum(header):
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
    total = (total >> 16) + (total & 0xFFFF)
    total = ~total & 0xFFFF
    return struct.pack('>H', total)

def create_ipv4_header(row):
    # Extract IPv4 fields
    ipv4_version_bits = process_field(row, 'ipv4_ver_', 4)
    ipv4_ihl_bits = process_field(row, 'ipv4_hl_', 4)
    ipv4_tos_bits = process_field(row, 'ipv4_tos_', 8)
    ipv4_total_length_bits = process_field(row, 'ipv4_tl_', 16)
    ipv4_identification_bits = process_field(row, 'ipv4_id_', 16)
    ipv4_flags_bits = process_field(row, 'ipv4_rbit_', 1) + process_field(row, 'ipv4_dfbit_', 1) + process_field(row, 'ipv4_mfbit_', 1)
    ipv4_frag_offset_bits = process_field(row, 'ipv4_foff_', 13)
    ipv4_ttl_bits = process_field(row, 'ipv4_ttl_', 8)
    ipv4_proto_bits = b'\x06' #b'00000110'  # Binary for 6 (TCP)
    ipv4_checksum_bits = b'\x00\x00'  # Placeholder for checksum
    ipv4_src_ip_bits = process_field(row, 'ipv4_src_', 32)
    ipv4_dst_ip_bits = process_field(row, 'ipv4_dst_', 32)
    ipv4_opt_bits = process_field(row, 'ipv4_opt_', 320)

    # Construct the IPv4 header without the checksum
    ipv4_header = (ipv4_version_bits + ipv4_ihl_bits + ipv4_tos_bits + ipv4_total_length_bits +
                   ipv4_identification_bits + ipv4_flags_bits + ipv4_frag_offset_bits +
                   ipv4_ttl_bits + ipv4_proto_bits + ipv4_checksum_bits + ipv4_src_ip_bits +
                   ipv4_dst_ip_bits + ipv4_opt_bits)

    # Calculate checksum and set it
    ipv4_checksum_bits = ipv4_checksum(ipv4_header)
    
    # Replace the checksum in the IPv4 header
    ipv4_header = ipv4_header[:10] + ipv4_checksum_bits + ipv4_header[12:]

    return ipv4_header

def tcp_checksum(source_ip, dest_ip, tcp_header):
    # Create the pseudo header
    pseudo_header = struct.pack('>4s4sBBH', 
                                 socket.inet_aton(source_ip), 
                                 socket.inet_aton(dest_ip), 
                                 0,  # Protocol (TCP)
                                 len(tcp_header))  # TCP length

    total = 0
    # Sum the pseudo header
    for i in range(0, len(pseudo_header), 2):
        total += (pseudo_header[i] << 8) + (pseudo_header[i + 1] if i + 1 < len(pseudo_header) else 0)

    # Sum the TCP header
    for i in range(0, len(tcp_header), 2):
        total += (tcp_header[i] << 8) + (tcp_header[i + 1] if i + 1 < len(tcp_header) else 0)

    # Fold 32-bit sum to 16 bits
    total = (total >> 16) + (total & 0xFFFF)
    total = ~total & 0xFFFF
    return struct.pack('>H', total)

def create_tcp_header(row, ipv4_src_ip, ipv4_dst_ip):
    # Extract TCP fields
    tcp_src_port_bits = process_field(row, 'tcp_sprt_', 16)
    tcp_dst_port_bits = process_field(row, 'tcp_dprt_', 16)
    tcp_seq_bits = process_field(row, 'tcp_seq_', 32)
    tcp_ack_bits = process_field(row, 'tcp_ackn_', 32)
    tcp_data_offset_bits = process_field(row, 'tcp_doff_', 4)
    tcp_flags_bits = (process_field(row, 'tcp_res', 3) + process_field(row, 'tcp_ns_', 1) +
                      process_field(row, 'tcp_cwr_', 1) + process_field(row, 'tcp_ece_', 1) +
                      process_field(row, 'tcp_urg_', 1) + process_field(row, 'tcp_ackf_', 1) +
                      process_field(row, 'tcp_psh_', 1) + process_field(row, 'tcp_rst_', 1) +
                      process_field(row, 'tcp_syn_', 1) + process_field(row, 'tcp_fin_', 1))
    tcp_window_bits = process_field(row, 'tcp_wsize_', 16)
    tcp_checksum_bits = b'\x00\x00'  # Placeholder for checksum
    tcp_urgent_ptr_bits = process_field(row, 'tcp_urp_', 16)
    tcp_opt_bits = process_field(row, 'tcp_opt_', 320)

    # Construct the TCP header without the checksum
    tcp_header = (tcp_src_port_bits + tcp_dst_port_bits + tcp_seq_bits + tcp_ack_bits +
                  tcp_data_offset_bits + tcp_flags_bits + tcp_window_bits +
                  tcp_checksum_bits + tcp_urgent_ptr_bits + tcp_opt_bits)

    # Calculate the TCP checksum
    tcp_checksum_bits = tcp_checksum(ipv4_src_ip, ipv4_dst_ip, tcp_header)

    # Replace the checksum in the TCP header
    tcp_header = tcp_header[:16] + tcp_checksum_bits + tcp_header[18:]

    return tcp_header


def bits_to_bytes(bits):
    if not bits:
        return b''
    # Pad bits to ensure the length is a multiple of 8
    padding_length = (8 - len(bits) % 8) % 8
    bits += '0' * padding_length
    return int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')

def process_field(row, prefix, length):
    """Process a field with given prefix and bit length"""
    cols = [col for col in row.index if col.startswith(prefix)]
    bits = ''.join(str(row[col]) for col in cols if row[col] != -1)
    if len(bits) > length:
        raise ValueError(f"Field {prefix} has more bits than expected ({length})")
    return bits_to_bytes(bits)

def csv_to_raw_packets(csv_file, output_file):
    # Load CSV file
    df = pd.read_csv(csv_file)

    # Write PCAP global header
    with open(output_file, 'wb') as f:
        f.write(create_pcap_header())
        
        for index, row in df.iterrows():
            try:
                #print(f"Processing row {index}: {row.to_dict()}")  # Debug: Print the row data
                #print(f"Processing row {index+1}")  # Debug: Print the row data

                # Create IPv4 header using the function
                ipv4_header = create_ipv4_header(row)
                
                # Extract source and destination IPs for TCP header
                ipv4_src_ip = bits_to_bytes(process_field(row, 'ipv4_src_', 32))
                ipv4_dst_ip = bits_to_bytes(process_field(row, 'ipv4_dst_', 32))

                # Create TCP header using this function
                tcp_header = create_tcp_header(row, ipv4_src_ip, ipv4_dst_ip)

                # Add Ethernet header and combine IPv4 and TCP headers
                ethernet_header = create_ethernet_header()
                packet_data = ethernet_header + ipv4_header + tcp_header

                # Write PCAP packet header and data
                timestamp = 0  # Use a real timestamp or calculated one
                length = len(packet_data)
                f.write(create_pcap_packet_header(timestamp, length))
                f.write(packet_data)  # Directly write bytes

                print(f"Ethernet Header (hex): {ethernet_header.hex()}")
                print(f"IPv4 Header (hex): {ipv4_header.hex()}")
                print(f"TCP Header (hex): {tcp_header.hex()}")
                print(f"Packet written to file: {packet_data.hex()}")

            except ValueError as e:
                print(f"Error processing packet for row {index}: {e}")
            except Exception as e:
                print(f"Error constructing packet for row {index}: {e}")

# Usage
csv_to_raw_packets('./examples/port443_testing.npt', 'output.pcap')
