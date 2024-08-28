import pandas as pd
from scapy.all import *

def bits_to_bytes(bits):
    if not bits:
        return b''
    # Pad bits to ensure the length is a multiple of 8
    padding_length = (8 - len(bits) % 8) % 8
    bits += '0' * padding_length
    print(f"Bits: {bits}")  # Debug: Print the bits before conversion
    return int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')

def process_field(row, prefix, length):
    """Process a field with given prefix and bit length"""
    cols = [col for col in row.index if col.startswith(prefix)]
    bits = ''.join(str(row[col]) for col in cols if row[col] != -1)
    if len(bits) > length:
        raise ValueError(f"Field {prefix} has more bits than expected ({length})")
    print(f"Processing {prefix}: {bits}")  # Debug: Print the bits being processed
    return bits_to_bytes(bits)

def csv_to_packets(csv_file):
    # Load CSV file
    df = pd.read_csv(csv_file)

    #print(df)
    #sys.exit(0)

    packets = []

    # Process each row in the CSV
    for index, row in df.iterrows():
        try:
            print(f"Processing row {index}: {row.to_dict()}")  # Debug: Print the row data

            # Extract IPv4 fields
            ipv4_version_bits = process_field(row, 'ipv4_ver_', 4)
            ipv4_ihl_bits = process_field(row, 'ipv4_hl_', 4)
            ipv4_tos_bits = process_field(row, 'ipv4_tos_', 8)
            ipv4_total_length_bits = process_field(row, 'ipv4_tl_', 16)
            ipv4_identification_bits = process_field(row, 'ipv4_id_', 16)
            ipv4_flags_bits = process_field(row, 'ipv4_rbit_', 1) + process_field(row, 'ipv4_dfbit_', 1) + process_field(row, 'ipv4_mfbit_', 1)
            ipv4_frag_offset_bits = process_field(row, 'ipv4_foff_', 13)
            ipv4_ttl_bits = process_field(row, 'ipv4_ttl_', 8)
            ipv4_proto_bits = process_field(row, 'ipv4_proto_', 8)
            ipv4_checksum_bits = process_field(row, 'ipv4_cksum_', 16)
            ipv4_src_ip_bits = process_field(row, 'ipv4_src_', 32)
            ipv4_dst_ip_bits = process_field(row, 'ipv4_dst_', 32)
            ipv4_opt_bits = process_field(row, 'ipv4_opt_', 320)

            ipv4_header = ipv4_version_bits + ipv4_ihl_bits + ipv4_tos_bits + ipv4_total_length_bits + \
                           ipv4_identification_bits + ipv4_flags_bits + ipv4_frag_offset_bits + \
                           ipv4_ttl_bits + ipv4_proto_bits + ipv4_checksum_bits + ipv4_src_ip_bits + \
                           ipv4_dst_ip_bits + ipv4_opt_bits

            # Extract TCP fields
            tcp_src_port_bits = process_field(row, 'tcp_sprt_', 16)
            tcp_dst_port_bits = process_field(row, 'tcp_dprt_', 16)
            tcp_seq_bits = process_field(row, 'tcp_seq_', 32)
            tcp_ack_bits = process_field(row, 'tcp_ackn_', 32)
            tcp_data_offset_bits = process_field(row, 'tcp_doff_', 4)
            tcp_flags_bits = process_field(row, 'tcp_res', 3) + process_field(row, 'tcp_ns_', 1) + process_field(row, 'tcp_cwr_', 1) + \
                             process_field(row, 'tcp_ece_', 1) + process_field(row, 'tcp_urg_', 1) + \
                             process_field(row, 'tcp_ackf_', 1) + process_field(row, 'tcp_psh_', 1) + \
                             process_field(row, 'tcp_rst_', 1) + process_field(row, 'tcp_syn_', 1) + \
                             process_field(row, 'tcp_fin_', 1)
            tcp_window_bits = process_field(row, 'tcp_wsize_', 16)
            tcp_checksum_bits = process_field(row, 'tcp_cksum_', 16)
            tcp_urgent_ptr_bits = process_field(row, 'tcp_urp_', 16)
            tcp_opt_bits = process_field(row, 'tcp_opt_', 320)

            tcp_header = tcp_src_port_bits + tcp_dst_port_bits + tcp_seq_bits + tcp_ack_bits + \
                         tcp_data_offset_bits + tcp_flags_bits + tcp_window_bits + tcp_checksum_bits + \
                         tcp_urgent_ptr_bits + tcp_opt_bits

            # Combine IPv4 and TCP headers
            packet_data = bytes(ipv4_header) + bytes(tcp_header)
            
            # Debugging TCP fields and packet_data
            print(f"Packet Data (Hex): {packet_data.hex()}")

            # Create packet
            packet = Ether() / IP() / TCP() / Raw(load=packet_data)
            print(f"Packet: {packet}")  # Debug: Print the constructed packet
            packets.append(packet)
        
        except ValueError as e:
            print(f"Error processing packet for row {index}: {e}")
        except Exception as e:
            print(f"Error constructing packet for row {index}: {e}")

    return packets

# Usage
packets = csv_to_packets('./examples/port443_testing.npt')

# Save packets to PCAP
with PcapWriter('output.pcap', append=True, sync=True) as pcap_writer:
    for pkt in packets:
        print(f"Writing packet: {pkt}")  # Debug: Print packet being written
        pcap_writer.write(pkt)
