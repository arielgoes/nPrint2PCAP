import pandas as pd
from scapy.all import *

def bits_to_bytes(bits):
    if not bits:
        return b''
    #print(f"Bits: {bits}")  # Debug: Print the bits before conversion
    output = int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')
    #print("output: ", output)
    return output
    

def process_field(row, prefix, length):
    """Process a field with given prefix and bit length"""
    cols = [col for col in row.index if col.startswith(prefix)]
    bits = ''.join(str(row[col]) for col in cols if row[col] != -1)
    if len(bits) > length:
        raise ValueError(f"Field {prefix} has more bits than expected ({length})")
    #print(f"Processing {prefix}: {bits}")  # Debug: Print the bits being processed
    return bits

def csv_to_packets(csv_file):
    # Load CSV file
    df = pd.read_csv(csv_file)

    packets = []

    # Process each row in the CSV
    for index, row in df.iterrows():
        try:
            #print(f"Processing row {index}: {row.to_dict()}")  # Debug: Print the row data

            # Extract IPv4 fields
            ipv4_prefixes = {'ipv4_ver_':4,
                             'ipv4_hl_':4,
                             'ipv4_tos_':8,
                             'ipv4_tl_':16,
                             'ipv4_id_':16,
                             'ipv4_rbit_':1, 'ipv4_dfbit_':1, 'ipv4_mfbit_':1,
                             'ipv4_foff_':13,
                             'ipv4_ttl_':8,
                             'ipv4_proto_':8,
                             'ipv4_cksum_':16,
                             'ipv4_src_':32,
                             'ipv4_dst_':32,
                             'ipv4_opt_':320}
            
            bits = ''
            total = []
            for prefix, length in ipv4_prefixes.items():
                bits += process_field(row, prefix, length)
                if len(bits) % 8 == 0:
                    total.append(bits_to_bytes(bits))
                    bits = ''
                    #print()

            # Concatenate using the `+` operator
            ipv4_header = b''.join(total)
            #print("IPv4 (concatenated): ", ipv4_header)

            # Extract TCP fields            
            tcp_prefixes = {'tcp_sprt_':16,
                            'tcp_dprt_':16,
                            'tcp_seq_':32,
                            'tcp_ackn_':32,
                            'tcp_doff_':4,
                            'tcp_res_':3, 'tcp_ns_':1, 'tcp_cwr_':1,
                            'tcp_ece_':1, 'tcp_urg_':1,
                            'tcp_ackf_':1, 'tcp_psh_':1,
                            'tcp_rst_':1, 'tcp_syn_':1,
                            'tcp_fin_':1,
                            'tcp_wsize_':16,
                            'tcp_cksum_':16,
                            'tcp_urp_':16,
                            'tcp_opt_':320}
            
            bits = ''
            total = []
            for prefix, length in tcp_prefixes.items():
                #print(prefix, length)
                bits += process_field(row, prefix, length)
                #print("mod: ", len(bits) % 8)
                if len(bits) % 8 == 0:
                    total.append(bits_to_bytes(bits))
                    bits = ''
                    #print()

            # Concatenate using the `+` operator
            tcp_header = b''.join(total)
            #print("TCP (concatenated): ", tcp_header)

            # Combine IPv4 and TCP headers
            packet_data = ipv4_header + tcp_header

            
            # Debugging TCP fields and packet_data
            #print(f"Packet Data (Hex): {packet_data.hex()}")

            # Create packet
            packet = Ether(type=0x800) / Raw(load=packet_data)

            #print(f"Packet: {packet}")  # Debug: Print the constructed packet
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