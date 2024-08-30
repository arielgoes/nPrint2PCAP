import pandas as pd
from scapy.all import *

eth_prefixes = {'eth_dhost_':48,
                'eth_shost_':48,
                'eth_ethertype_':14}

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

ipv6_prefixes = {'ipv6_ver_':4,
                    'ipv6_tc_':8,
                    'ipv6_fl_':20,
                    'ipv6_len_':16,
                    'ipv6_nh_':8,
                    'ipv6_hl_':8,
                    'ipv6_src_':128,
                    'ipv6_dst_':128}

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

udp_prefixes = {'udp_sport_':16,
                'udp_dport_':16,
                'udp_len_':16,
                'udp_cksum_':16}

icmp_prefixes = {'icmp_type_':8,
                    'icmp_code_':8,
                    'icmp_cksum_':8,
                    'icmp_roh_':32}


def create_byte_representation(row, prefixes: dict):
    bits = ''
    total = []
    for prefix, length in prefixes.items():
        bits += process_field(row, prefix, length)
        if len(bits) % 8 == 0:
            total.append(bits_to_bytes(bits))
            bits = ''
    return total


def bits_to_bytes(bits):
    if not bits:
        return b''
    #print(f"Bits: {bits}")  # Debug: Print the bits before conversion
    return int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')
    


def process_field(row, prefix, length):
    """Process a field with given prefix and bit length"""
    cols = [col for col in row.index if col.startswith(prefix)]
    bits = ''.join(str(row[col]) for col in cols if row[col] != -1)
    if len(bits) > length:
        raise ValueError(f"Field {prefix} has more bits than expected ({length})")
    print(f"Processing {prefix}: {bits}")  # Debug: Print the bits being processed
    return bits


def generate_unique_random_mac(rnd_mac_unique): # a list to monitor and guarante unique random MACs are being generated
    #Generates a random UNIQUE MAC address in the format 'XX:XX:XX:XX:XX:XX'.
    mac_address = [random.randint(0, 255) for _ in range(6)]
    mac_address[0] &= 0xfe  # Ensure the first byte is even (unicast address)
    mac_address = ":".join(hex(x)[2:].zfill(2) for x in mac_address)
    
    while mac_address in rnd_mac_unique: # NOTE: if there is no more unique MACs available, this function may be in an infinite loop!
        mac_address = [random.randint(0, 255) for _ in range(6)]
        mac_address[0] &= 0xfe  # Ensure the first byte is even (unicast address)
        mac_address = ":".join(hex(x)[2:].zfill(2) for x in mac_address)
    return mac_address


def binary_to_ip_string(binary_ip):
  """Converts a 32-bit binary IP address to its string representation.
  Raises:
    ValueError: If the binary IP is not 32 bits long.
  """

  if len(binary_ip) != 32:
    raise ValueError("Binary IP address must be 32 bits long")

  # Split the binary IP into four 8-bit octets
  octets = [binary_ip[i:i+8] for i in range(0, 32, 8)]

  # Convert each octet to its decimal equivalent
  decimal_octets = [int(octet, 2) for octet in octets]

  # Join the decimal octets with dots
  ip_string = ".".join(map(str, decimal_octets))
  return ip_string


def csv_to_packets(filename):

    #print(df.shape[0]) # df.shape: (lines, columns)
    
    min_lines = 1 # if file has less than one line (not considering the header),
                  # it contains either the header
                  # (or badly positioned bit information e.g., 0,1,0,...)
    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        raise FileNotFoundError(f"File '{filename}' not found.")
    if len(df) < min_lines:
        raise ValueError(f"File '{filename}' has fewer than {min_lines} lines.")
    first_line = df.iloc[0, 0]
    if first_line.isdigit():
        raise ValueError(f"File '{filename}' is malformed: First line should not start with a number.")

    packets = []
    rnd_mac_unique = []
    ipv4_to_mac_dict = {}
    # Process each row in the CSV
    for index, row in df.iterrows():
        try:
            #print(f"Processing row {index}: {row.to_dict()}")  # Debug: Print the row data

            
            # Concatenate the bits to form a minimal value that is multiple of 8 and create bytes (or bytes) from it.
            # For example: ipv4 version (4 bits) + ipv4 hl (4 bits) sum up to 8. So, gather these fields and create a byte.
            total = create_byte_representation(row, ipv4_prefixes)

            # Concatenate using the `+` operator
            ipv4_header = b''.join(total)
            print("IPv4 (concatenated): ", ipv4_header)
            print()

            ##########################################################################

            
            # Concatenate the bits to form a minimal value that is multiple of 8 and create bytes (or bytes) from it.
            total = create_byte_representation(row, tcp_prefixes)

            # Concatenate using the `+` operator
            tcp_header = b''.join(total)
            #print("TCP (concatenated): ", tcp_header)

        

            # payload for IPv4/TCP 
            payload = int(process_field(row, 'ipv4_tl', 16),2) - len(ipv4_header) - len(tcp_header) # TCP payload = IPv4 total len (field) - IPv4 len - (TCP data offset * 4)
            payload = b'\x00' * payload
            packet_data = ipv4_header + tcp_header + payload
            
            # Debugging the packet data
            #print(f"Packet Data (Hex): {packet_data.hex()}")

            # Save the unique IPs to create ethernet header
            prefix = 'ipv4_src_'
            length = 32
            ipv4_src = process_field(row, prefix, length)
            ipv4_src = binary_to_ip_string(ipv4_src)
            #
            prefix = 'ipv4_dst_'
            length = 32
            ipv4_dst = process_field(row, prefix, length)
            ipv4_dst = binary_to_ip_string(ipv4_dst)
            #
            #print("ipv4_src (string):", ipv4_src)
            #print("ipv4_dst (string):", ipv4_dst)

            # Generate a random unique MAC
            rnd_mac = generate_unique_random_mac(rnd_mac_unique)
            #print("rnd_mac:", rnd_mac)

            if ipv4_src not in ipv4_to_mac_dict:
                ipv4_to_mac_dict[ipv4_src] = rnd_mac
            
            # Generate a random unique MAC
            rnd_mac = generate_unique_random_mac(rnd_mac_unique)
            #print("rnd_mac:", rnd_mac)

            if ipv4_dst not in ipv4_to_mac_dict:
                ipv4_to_mac_dict[ipv4_dst] = rnd_mac

            for key, value in ipv4_to_mac_dict.items():
                print(key, value)

            # Create packet
            packet = Ether(src=ipv4_to_mac_dict[ipv4_src], dst=ipv4_to_mac_dict[ipv4_dst], type=0x800) / Raw(load=packet_data)
            print("packet len:", len(packet))

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