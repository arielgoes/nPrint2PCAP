import pandas as pd
from scapy.all import *
import argparse
import numpy as np
import math

# COLORIZING
none = '\033[0m'
bold = '\033[01m'
disable = '\033[02m'
underline = '\033[04m'
reverse = '\033[07m'
strikethrough = '\033[09m'
invisible = '\033[08m'
green = '\033[32m'


eth_prefixes = {'eth_dhost_':48,
                'eth_shost_':48,
                'eth_ethertype_':16}

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

payload = {} # if "payload_<#>" columns exist, this dictionary will be dynamically populated.


def binary_to_decimal(binary_list):
    #print("binary_list:", binary_list)
    """Convert a binary list representation to its decimal equivalent."""
    binary_str = ''.join(map(str, binary_list))
    return int(binary_str, 2)


def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def compute_ipv4_checksum(header_bytes):
    # Zero out the checksum field
    header_bytes = bytearray(header_bytes)
    #print("header_bytes:",header_bytes[10:12])
    header_bytes[10:12] = b'\x00\x00' # initially fill the IPv4 checksum field with 0x0000
    
    # Calculate checksum
    checksum = calculate_checksum(header_bytes)
    #print("Calculated Checksum (IPv4):", format(checksum, '04X'))  # Format as hex with leading zeros
    
    # Insert checksum into header
    header_bytes[10:12] = checksum.to_bytes(2, byteorder='big')
    return header_bytes


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
    output = int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')
    #print("output:", output)
    return output
    

def process_field(row, prefix, length):
    """Process a field with given prefix and bit length"""
    cols = [col for col in row.index if col.startswith(prefix)]
    bits = ''.join(str(int(row[col])) for col in cols if row[col] != -1)
    if len(bits) > length:
        raise ValueError(f"Field {prefix} has more bits than expected ({length}). Bits found: {bits}")
    #print(f"Processing {prefix}: {bits}")  # Debug: Print the bits being processed
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


def binary_to_ipv4_string(binary_ip):
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


def binary_to_port_string(binary_port):
    """Converts a 16-bit binary port to its decimal string representation.
    Raises:
        ValueError: If the binary port is not 16 bits long.
    """
    if len(binary_port) != 16:
        raise ValueError("Binary port must be 16 bits long")

    # Convert the 16-bit binary port to its decimal equivalent
    port_number = int(binary_port, 2)

    return str(port_number)


def verify_set_ports(row, df, prefix_list) -> str:
    """Checks and converts binary port values for TCP and UDP protocols.
    Arguments:
        row: The current row in the DataFrame.
        df: The DataFrame containing the protocol data.
        prefix_list: List of protocol prefixes (e.g., ['tcp_', 'udp_']).
    
    Returns:
        ports: A string representing the set ports for TCP or UDP protocols.
    """
    ports = ''
    for prefix in prefix_list:
        cols = df.columns[df.columns.str.contains(prefix)]
        if len(cols) > 0:
            first_col_with_substring = cols[0]
            if int(row[first_col_with_substring]) != -1:
                # Assuming the next 16 columns represent the port number in binary (e.g., tcp_port_0 to tcp_port_15)
                binary_port = ''.join([str(row[col]) for col in cols[:16]])
                ports += f"{prefix}port:{binary_to_port_string(binary_port)} "
    return ports.strip()


# Assumes a correctly pre-processed nPrint file as input (i.e., no cases such as ",1,-1,1," and so on)
def verify_set_protocols(row, df, prefix_list) -> str:
    protocols=''
    #print("prefix_list:", prefix_list)
    for prefix in prefix_list:
        cols = df.columns[df.columns.str.contains(prefix)]
        if len(cols) > 0:
            first_col_with_substring = cols[0]
            converted = int(row[first_col_with_substring])
            #print("converted:", converted)
            if converted != -1: # if has col and the row's first col is != -1 (e.g., ipv4_ver_0),
                                                              # set protocol. NOTE: We assume the remaining cols of this protocol
                                                              # are correctly set (i.e., no '-1' in between) 
                protocols += prefix
    return protocols




def ipv4_ver_formatting(df):
    #following is placeholder, how do we get payload size?:
    # Define the substrings that have static values, e.g., ip version = 4
    fields = ["ipv4_ver_"]
    matching_columns = df.filter(like="ipv4_ver_").columns
    #print("matching columns: ", matching_columns)

    # Iterate over the columns of the source DataFrame
    for column in matching_columns:
        # Check if the substring exists in the column name
        for field in fields:
            if field in column:
                # limited to ipv4
                if '0' in column:
                    df[column] = 0
                elif '1' in column:
                    df[column] = 1
                elif '2' in column:
                    df[column] = 0
                else:
                    df[column] = 0
    return df


def ipv4_header_negative_removal(df):
    fields = ["ipv4"]
    matching_columns = df.filter(like="ipv4").columns

    # Function to apply to each cell
    def replace_negative_one(val):
        if val == -1:
            return np.random.randint(0, 2)  # Generates either 0 or 1
        else:
            return val

    # Iterate over the columns of the source DataFrame
    for column in matching_columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column and 'opt' not in column:
                df[column] = df[column].apply(replace_negative_one)
            # ######## no opt for debugging
            # elif field in column:
            #     df[column] = -1
    return df


def protocol_determination(df):
    protocols = ["tcp", "udp", "icmp"]
    percentages_proto = {}

    # Iterate over the protocols
    for protocol in protocols:
        columns = [col for col in df.columns if protocol in col and 'opt' not in col]

        # Count non-negatives in each column and calculate the total percentage for each protocol
        total_count = 0
        non_negative_count = 0
        for column in columns:
            total_count += len(df[column])
            non_negative_count += (df[column] >= 0).sum()

        # Calculate percentage and store in the dictionary
        if total_count > 0:
            percentages_proto[protocol] = (non_negative_count / total_count) * 100
        else:
            percentages_proto[protocol] = 0

    # Find protocol with the highest percentage of non-negative values
    max_protocol = max(percentages_proto, key=percentages_proto.get)
    return max_protocol


def ipv4_pro_formatting(df, dominating_protocol):
    #following is placeholder, how do we get payload size?:
    # Define the substrings that have static values, e.g., ip version = 4

    # Call the function to determine the protocol
    #dominating_protocol = protocol_determination(df)
    print(dominating_protocol)
    # tcp = 0,0,0,0,0,1,1,0
    # udp = 0,0,0,1,0,0,0,1
    # icmp = 0,0,0,0,0,0,0,1
    fields = ["ipv4_pro"]
    matching_columns = df.filter(like="ipv4_pro").columns

    # Iterate over the columns of the source DataFrame
    for column in matching_columns:
        # Check if the substring exists in the column name
        for field in fields:
            if field in column:
                if dominating_protocol == 'tcp':
                    if '_0' in column:
                        df[column] = 0
                    elif '_1' in column:
                        df[column] = 0
                    elif '_2' in column:
                        df[column] = 0
                    elif '_3' in column:
                        df[column] = 0
                    elif '_4' in column:
                        df[column] = 0
                    elif '_5' in column:
                        df[column] = 1
                    elif '_6' in column:
                        df[column] = 1
                    elif '_7' in column:
                        df[column] = 0
                elif dominating_protocol == 'udp':
                    if '_0' in column:
                        df[column] = 0
                    elif '_1' in column:
                        df[column] = 0
                    elif '_2' in column:
                        df[column] = 0
                    elif '_3' in column:
                        df[column] = 1
                    elif '_4' in column:
                        df[column] = 0
                    elif '_5' in column:
                        df[column] = 0
                    elif '_6' in column:
                        df[column] = 0
                    elif '_7' in column:
                        df[column] = 1
                elif dominating_protocol == 'icmp':
                    if '_0' in column:
                        df[column] = 0
                    elif '_1' in column:
                        df[column] = 0
                    elif '_2' in column:
                        df[column] = 0
                    elif '_3' in column:
                        df[column] = 0
                    elif '_4' in column:
                        df[column] = 0
                    elif '_5' in column:
                        df[column] = 0
                    elif '_6' in column:
                        df[column] = 0
                    elif '_7' in column:
                        df[column] = 1

                # Copy the column values to the destination DataFrame
                #df[column] = formatted_nprint[column]
    # make sure non-dominant-protocol values are -1s
    protocols = ["tcp", "udp", "icmp"]
    for column in matching_columns:
        # Check if the substring exists in the column name
        for protocol in protocols:
            if protocol in column:
                if protocol != dominating_protocol:
                    df[column] = -1

    return df


def ipv4_option_removal(df):
    fields = ["ipv4_opt"]
    matching_columns = df.filter(like="ipv4_opt_").columns

    # Iterate over the columns of the source DataFrame
    for column in matching_columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column:
                df[column] = -1
            # ######## no opt for debugging
            # elif field in column:
            #     df[column] = -1

    return df


def ipv4_ttl_ensure(df):
    for index in range(0, len(df)):
        ttl_0 = True
        for j in range(8):
            if df.at[index, f'ipv4_ttl_{j}'] != 0:
                ttl_0 = False
        if ttl_0 == True:
            df.at[index, 'ipv4_ttl_7'] = 1
    return df


def ipv4_hl_formatting(df):
    # Get the subset of columns containing 'ipv4'
    matching_columns = df.filter(like='ipv4')
    # For each row in the DataFrame
    for idx, row in matching_columns.iterrows():
        # Count the 1s and 0s in this row
        count = (row == 1).sum() + (row == 0).sum()
        #print(count)
        # Convert to 32-bit/4-byte words
        header_size_words = math.ceil(count / 32)

        # Convert to binary and pad with zeroes to get a 4-bit representation
        binary_count = format(header_size_words, '04b')
        # Update the 'ipv4_hl' columns in the original DataFrame based on this binary representation
        for i in range(4):
            df.at[idx, f'ipv4_hl_{i}'] = int(binary_count[i])
    return df


def tcp_header_negative_removal(df):
    fields = ["tcp"]
    matching_columns = df.filter(like='tcp')

    # Function to apply to each cell
    def replace_negative_one(val):
        if val == -1:
            return np.random.randint(0, 2)  # Generates either 0 or 1
        else:
            return val

    # Iterate over the columns of the source DataFrame
    for column in matching_columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column and 'opt' not in column:
                df[column] = df[column].apply(replace_negative_one)
            # ######## no opt for debugging
            # elif field in column:
            #     df[column] = -1
    return df


def udp_header_negative_removal(df):
    fields = ["udp"]
    matching_columns = df.filter(like='udp')

    # Function to apply to each cell
    def replace_negative_one(val):
        if val == -1:
            return np.random.randint(0, 2)  # Generates either 0 or 1
        else:
            return val

    # Iterate over the columns of the source DataFrame
    for column in matching_columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column and 'opt' not in column:
                df[column] = df[column].apply(replace_negative_one)
            # ######## no opt for debugging
            # elif field in column:
            #     df[column] = -1
    return df


def modify_tcp_option(packet):
    # This function processes each packet of the dataframe and modifies the TCP option fields to align with the actual structure of the TCP options.
    option_data = packet.loc['tcp_opt_0':'tcp_opt_319'].to_numpy()
    idx = 0
    options_lengths = [0, 8, 32, 24, 16, 40, 80]  # NOP/EOL, MSS, Window Scale, SACK Permitted, SACK, Timestamp

    while idx < 320:
        start_idx = idx
        end_idx = idx
        while end_idx < 320 and option_data[end_idx] != -1:
            end_idx += 1
        length = end_idx - start_idx
        closest_option = min(options_lengths, key=lambda x: abs(x - length))

        if closest_option == 32:  # MSS
            #print('mss')
            idx += 32
            mss_data = np.concatenate(([0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0], option_data[start_idx+16:idx]))
            mss_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in mss_data]
            option_data[start_idx:idx] = mss_data
            options_lengths.remove(closest_option)
        elif closest_option == 24:  # Window Scale
            #print('ws')
            idx += 24
            ws_data =  np.concatenate(([0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1], option_data[start_idx+16:idx]))
            ws_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in ws_data]
            option_data[start_idx:idx] = ws_data
            options_lengths.remove(closest_option)
        elif closest_option == 16:  # SACK Permitted
            #print('sack permitted')
            idx += 16
            option_data[start_idx:idx] = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
            options_lengths.remove(closest_option)

        elif closest_option == 40:  # SACK (Assuming one block for simplicity)
            # Assuming the length would be for one SACK block: kind (1 byte), length (1 byte, value 10 for one block), and 8 bytes of data.
            idx+=40
            sack_data = np.concatenate(([0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0], option_data[start_idx+16:idx]))
            sack_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in sack_data]
            option_data[start_idx:idx] = sack_data
            options_lengths.remove(closest_option)

        elif closest_option == 80:  # Timestamp
            #print('time stamp')
            idx += 80
            ts_data = np.concatenate(([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0], option_data[start_idx+16:idx]))
            ts_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in ts_data]
            option_data[start_idx:idx] = ts_data
            options_lengths.remove(closest_option)

        elif closest_option == 8:  # 
            #print('eol/nop')
            if option_data[start_idx] == 0:  # EOL
                if start_idx == 0:
                    idx += 8
                    option_data[start_idx:idx] = [-1,-1,-1,-1,-1,-1,-1,-1]
                    options_lengths.remove(closest_option)
                    continue
                else:
                    idx += 8
                    option_data[start_idx:idx] = [0,0,0,0,0,0,0,0]
                    option_data[idx:] = [-1] * (320 - idx)
                    options_lengths.remove(closest_option) 
                    break
            elif option_data[start_idx] == 1:  # NOP
                idx += 8
                option_data[start_idx:idx] = [0,0,0,0,0,0,0,1]
        elif closest_option == 0:
            idx += 8
            option_data[start_idx:idx] = [-1,-1,-1,-1,-1,-1,-1,-1]

    # Assign back the modified options to the DataFrame's row
    packet.loc['tcp_opt_0':'tcp_opt_319'] = option_data
    return packet


def tcp_opt_formatting(generated_nprint):
    generated_nprint = generated_nprint.apply(modify_tcp_option, axis=1)
    return generated_nprint


def tcp_data_offset_calculation(df):
    # Get the subset of columns containing 'tcp'
    tcp_columns = df.filter(like='tcp')
    # For each row in the DataFrame
    for idx, row in tcp_columns.iterrows():
        # Count the 1s and 0s in this row
        count = (row == 1).sum() + (row == 0).sum()
        # Convert to 32-bit/4-byte words
        header_size_words = math.ceil(count / 32)
        # Convert to binary and pad with zeroes to get a 4-bit representation
        binary_count = format(header_size_words, '04b')
        # Update the 'ipv4_hl' columns in the original DataFrame based on this binary representation
        for i in range(4):
            df.at[idx, f'tcp_doff_{i}'] = int(binary_count[i])
    return df


def udp_len_calculation(df):
    # For each row in the DataFrame
    for idx, row in df.iterrows():
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'] for i in range(4)]
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        upper_limit = 1500 - ipv4_hl_value - 8
        udp_len_binary = [row[f'udp_len_{i}'] for i in range(16)]
        udp_len_value = binary_to_decimal(udp_len_binary)  # Convert from 4-byte words to bytes
        if udp_len_value >= 8 and udp_len_value <= upper_limit:
            continue
        elif udp_len_value < 8:
            for i in range(16):
                df.at[idx, f'udp_len_{i}'] = 0
            df.at[idx, f'udp_len_12'] = 1
        else:
            new_udp_len_binary = format(upper_limit, '016b')
            for i in range(16):
                df.at[idx, f'udp_len_{i}'] = int(new_udp_len_binary[i])
    return df


def ipv4_tl_formatting_tcp(df):

    counter = 0
    for idx, row in df.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'].astype('int8') for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'].astype('int8') for i in range(4)]
        tcp_doff_binary = [row[f'tcp_doff_{i}'].astype('int8') for i in range(4)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        tcp_doff_value = binary_to_decimal(tcp_doff_binary) * 4  # Convert from 4-byte words to bytes
        # Checking and setting the new value if condition is met
        if ipv4_tl_value < ipv4_hl_value + tcp_doff_value:
            new_ipv4_tl_value = ipv4_hl_value + tcp_doff_value
            # Convert new value back to binary and update the fields
            new_ipv4_tl_binary = format(new_ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                df.at[idx, f'ipv4_tl_{i}'] = int(bit)
        elif ipv4_tl_value>1500:
            new_ipv4_tl_binary = format(1500, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                df.at[idx, f'ipv4_tl_{i}'] = int(bit)
        else:
            new_ipv4_tl_binary = format(ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                df.at[idx, f'ipv4_tl_{i}'] = int(bit)
    # for i in range(16):
    #     df[f'ipv4_tl_{i}'] = formatted_nprint[f'ipv4_tl_{i}']
    for idx, row in df.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'].astype('int8') for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'].astype('int8') for i in range(4)]
        tcp_doff_binary = [row[f'tcp_doff_{i}'].astype('int8') for i in range(4)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        tcp_doff_value = binary_to_decimal(tcp_doff_binary) * 4  # Convert from 4-byte words to bytes
        # print(f'Packet {counter}:')
        # print('ipv4 total length in bytes:')
        # print(ipv4_tl_value)
        # print('ipv4 header length in bytes:')
        # print(ipv4_hl_value)
        # print('tcp doff in bytes:')
        # print(tcp_doff_value)
        # print()
        counter +=1
    return df



def ipv4_tl_formatting_udp(df):
    counter = 0
    for idx, row in df.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'].astype('int8') for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'].astype('int8') for i in range(4)]
        udp_len_binary = [row[f'udp_len_{i}'].astype('int8') for i in range(16)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        udp_len_value = binary_to_decimal(udp_len_binary)  # Convert from 4-byte words to bytes
        # Checking and setting the new value if condition is met
        if ipv4_tl_value < ipv4_hl_value + udp_len_value:
            new_ipv4_tl_value = ipv4_hl_value + udp_len_value
            # Convert new value back to binary and update the fields
            new_ipv4_tl_binary = format(new_ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                df.at[idx, f'ipv4_tl_{i}'] = int(bit)
        elif ipv4_tl_value>1500:
            new_ipv4_tl_binary = format(1500, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                df.at[idx, f'ipv4_tl_{i}'] = int(bit)
        else:
            new_ipv4_tl_binary = format(ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                df.at[idx, f'ipv4_tl_{i}'] = int(bit)
    # for i in range(16):
    #     df[f'ipv4_tl_{i}'] = formatted_nprint[f'ipv4_tl_{i}']
    for idx, row in df.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'].astype('int8') for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'].astype('int8') for i in range(4)]
        udp_len_binary = [row[f'udp_len_{i}'].astype('int8') for i in range(16)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        udp_len_value = binary_to_decimal(udp_len_binary) # Convert from 4-byte words to bytes
        counter +=1
    return df


def verify_and_correct_fields(df):
    ##### IPv4
    # assuming IPv4 so far, the function below finds out if most of the fields are enabled (i.e., != -1) for TCP or UDP
    dominating_protocol = protocol_determination(df)
    
    df = ipv4_ver_formatting(df) # we are using ipv4 only
    df = ipv4_header_negative_removal(df) # here we make sure minimum ipv4 header size is achieved - no missing ipv4 header fields, random int is assigned as the fields largely are correct due to timeVAE
    df = ipv4_pro_formatting(df, dominating_protocol) # this is less flexible -> choose protocol with most percentage of non negatives excluding option, and change all non-determined-protocol fields to -1
    df = ipv4_option_removal(df) # mordern Internet rarely uses ipv4 options is used at all, from the data we observe ipv4 options are never present due to it being obsolete
    df = ipv4_ttl_ensure(df) # ensure ttl > 0
    df = ipv4_hl_formatting(df) # ipv4 header length formatting (this is computation based so we do not have flexibility here), need to be done after all other ipv4 fields are formatted


    if dominating_protocol == 'tcp':
        df = tcp_header_negative_removal(df)
        df = tcp_opt_formatting(df) # option must be continuous and has fixed length, we use closest approximation here
        df = tcp_data_offset_calculation(df) # count the total number of bytes in the tcp header fields including options and store the sume as the offset
        ########### IPV4
        df = ipv4_tl_formatting_tcp(df) # payload need to be considered
    elif dominating_protocol == 'udp':
        df = udp_header_negative_removal(df)
        df = udp_len_calculation(df) 
        ########### IPV4
        df = ipv4_tl_formatting_udp(df) # payload need to be considered

    # Define the substrings we're interested in
    substrings = ["eth_", "ipv4_", "ipv6_", "tcp_", "udp_", "icmp_", "wlan_", "radiotap_"] # we ignore 'payload_' since nPrint 1.2.1 fills with -1 anyway.
    
    # Find all columns that match any of these substrings
    columns_of_interest = [col for col in df.columns if any(sub in col for sub in substrings)]
    
    # Initialize the dictionary to store occurrences by row
    row_occurrences = {}
    
    # Check for malformed sequences
    for i in range(1, len(columns_of_interest) - 1):
        col_prev = columns_of_interest[i - 1]
        col_curr = columns_of_interest[i]
        col_next = columns_of_interest[i + 1]
        
        values_prev = df[col_prev].values
        values_curr = df[col_curr].values
        values_next = df[col_next].values

        for row_idx in range(len(values_curr)):
            if values_curr[row_idx] == -1 and (values_prev[row_idx] != -1 and values_next[row_idx] != -1):
                # Append occurrence to the dictionary
                if row_idx not in row_occurrences:
                    row_occurrences[row_idx] = []
                row_occurrences[row_idx].append([
                    col_prev,
                    col_curr,
                    col_next,
                    values_prev[row_idx],
                    values_curr[row_idx],
                    values_next[row_idx]])
    
    # Print the malformed occurrences by row (if any)
    if row_occurrences:
        #for row_idx, occurrences in row_occurrences.items():
        #    print(row_idx, occurrences)
        print(f'ERROR: Malformed sequences by rows above. There are {len(row_occurrences)} malformed rows!!')
        sys.exit(0)
    else:
        print("No malformed sequences found :)")

    return df, dominating_protocol


def add_flow_column(df, dominating_protocol):
    # placeholder port for ICMP
    placeholder = '70000'
    
    # Initialize an empty list to store the 'flow' column values
    flow_column = []
    
    # Iterate over each row in the DataFrame
    for index, row in df.iterrows():
        # Retrieve 'src_ip' and 'dst_ip' (only works for IPv4 so far)
        src_ip = process_field(row, 'ipv4_src_', 32)
        dst_ip = process_field(row, 'ipv4_dst_', 32)
        src_ip = binary_to_ipv4_string(src_ip)
        dst_ip = binary_to_ipv4_string(dst_ip)

        # Retrieve 'src_port' and 'dst_port' based on the dominant protocol
        if dominating_protocol == 'tcp':
            src_port = process_field(row, 'tcp_sprt_', 16)
            dst_port = process_field(row, 'tcp_dprt_', 16)
            src_port = binary_to_port_string(src_port)
            dst_port = binary_to_port_string(dst_port)
        elif dominating_protocol == 'udp':
            src_port = process_field(row, 'udp_sport_', 16)
            dst_port = process_field(row, 'udp_dport_', 16)
            src_port = binary_to_port_string(src_port)
            dst_port = binary_to_port_string(dst_port)
        elif dominating_protocol == 'icmp':  # ICMP has no ports
            src_port = placeholder
            dst_port = placeholder

        # Create the 5-tuple string
        final_string = f"{src_ip}_{dst_ip}_{src_port}_{dst_port}_{dominating_protocol}"

        # Append the 5-tuple string to the list
        flow_column.append(final_string)

    # Insert the 'flow' column to the leftmost position in the DataFrame
    df.insert(0, 'flow', flow_column)

    return df


def csv_to_packets(filename):

    #print(df.shape[0]) # df.shape: (lines, columns)
    
    min_lines = 1 # if file has less than one line (not considering the header),
                  # it contains either the header
                  # (or badly positioned bit information e.g., 0,1,0,...)
    try:
        #df = pd.read_csv(filename, header=0) # header is first row (row 0)
        df = pd.read_csv(filename, nrows=0) # header is first row (row 0)
    except FileNotFoundError:
        raise FileNotFoundError(f"File '{filename}' not found.")


    columns = pd.read_csv(filename, nrows=0).columns

    # Create a dictionary of dtypes where the first and third to 1089 columns are int8, and the 'rts' (relative timestamp) column is int32
    dtypes = {col: 'int8' for col in columns}

    if 'rts' in columns:
        dtypes['rts'] = 'float32'  # Make the second column float32
    elif 'tv_sec' in columns and 'tv_usec' in columns:
        dtypes['tv_sec'] = 'int32'
        dtypes['tv_usec'] = 'float32' 

    df = pd.read_csv(filename, usecols=range(0, len(pd.read_csv(filename, nrows=0).columns)), dtype=dtypes)

    # Drop any 'Unamed <#>' columns
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    #print(df.columns)
    #print("DATATYPES: ", df.dtypes)

    if len(df) < min_lines:
        raise ValueError(f"File '{filename}' has fewer than {min_lines} lines.")
    
    # Check/correct for invalid cases in the nPrint input file: | ,0,-1,0 | ,0,-1,1 | ,1,-1,0 | ,1,-1,1
    if verify_nprint:
        # assuming a dominant protocol for the entire nPrint file (as NetDiffusion did), let us do the same here
        df, dominating_protocol = verify_and_correct_fields(df)

        # add 'flow' as first column. Same as '-O 4' argument in nPrint
        df = add_flow_column(df, dominating_protocol)

        # Modify the filename by appending "_corrected" before the extension
        output_filename = input.replace(".npt", "_corrected.npt")

        # Save the DataFrame to the modified filename
        df.to_csv(output_filename, index=False)

    total_lines = df.shape[0]
    packets = []
    rnd_mac_unique = []
    ipv4_to_mac_dict = {}
    
    # Process each row in the CSV
    for index, row in df.iterrows():

        # Calculate the percentage of completion
        percentage = (index + 1) / total_lines * 100
        
        # Print the progress percentage
        print(f"Progress: {percentage:.2f}%", end="\r")

        try:
            #print(f"Processing row {index}: {row.to_dict()}")  # Debug: Print the row data
            
            prefix_list = ['eth_', 'ipv4_', 'tcp_', 'udp_']
            protocols = verify_set_protocols(row, df, prefix_list)

            #print("SET PROTOCOLS:", protocols)

            ##############
            ## IPv4/TCP ##
            ##############
            if protocols == 'ipv4_tcp_' or \
                protocols == 'eth_ipv4_tcp_' or \
                protocols == 'ipv4_tcp_payload_' or \
                protocols == 'eth_ipv4_tcp_payload_':
                
                ########## 
                ## IPv4 ##
                ########## 
                # Concatenate the bits to form a minimal value that is multiple of 8 and create bytes (or bytes) from it.
                # For example: ipv4 version (4 bits) + ipv4 hl (4 bits) sum up to 8. So, gather these fields and create a byte.
                total = create_byte_representation(row, ipv4_prefixes)

                # Concatenate using the `+` operator
                ipv4_header = b''.join(total)
                #print("ipv4 header:", bytearray(ipv4_header))

                #ipv4_header = bytearray(ipv4_header)
                #print("header_bytes:",header_bytes[10:12])
                #ipv4_header[10:12] = b'\x00\x00' # initially fill the IPv4 checksum field with 0x0000

                # Once we have the 'ipv4_header' fields, calculate the checksum for IPv4, but it is optional
                if checksum_ipv4:
                    ipv4_header = compute_ipv4_checksum(ipv4_header)
                    #print("Header with checksum:", ipv4_header)

                #########
                ## TCP ##
                #########
                # Concatenate the bits to form a minimal value that is multiple of 8 and create bytes (or bytes) from it.
                total = create_byte_representation(row, tcp_prefixes)
                
                # Concatenate using the `+` operator
                tcp_header = b''.join(total)
                    
                # payload for IPv4/TCP
                # fill the packet with a random payload if there is none
                payload = int(process_field(row, 'ipv4_tl', 16),2) - len(ipv4_header) - len(tcp_header) # TCP payload = IPv4 total len (field) - IPv4 len - (TCP data offset * 4)
                payload = b'\x00' * payload

                # Concatenate headers
                packet_data = ipv4_header + tcp_header + payload

                # Save the unique IPs to create ethernet header
                prefix = 'ipv4_src_'
                length_ip = 32
                ipv4_src = process_field(row, prefix, length_ip)
                ipv4_src = binary_to_ipv4_string(ipv4_src)
                #
                prefix = 'ipv4_dst_'
                length_ip = 32
                ipv4_dst = process_field(row, prefix, length_ip)
                ipv4_dst = binary_to_ipv4_string(ipv4_dst)
                
                # Generate a random unique MAC
                rnd_mac = generate_unique_random_mac(rnd_mac_unique)

                if ipv4_src not in ipv4_to_mac_dict:
                    ipv4_to_mac_dict[ipv4_src] = rnd_mac
                
                # Generate a random unique MAC
                rnd_mac = generate_unique_random_mac(rnd_mac_unique)

                if ipv4_dst not in ipv4_to_mac_dict:
                    ipv4_to_mac_dict[ipv4_dst] = rnd_mac

                # Create packet
                if 'eth_' in protocols:
                    ##############
                    ## Ethernet ##
                    ##############
                    total = create_byte_representation(row, eth_prefixes)
                    eth_header = b''.join(total)
                    packet_data = eth_header + packet_data
                    packet = Raw(load=packet_data)
                else:
                    if checksum_tcp:
                        tcp_header = bytearray(tcp_header)
                        tcp_header[16:18] = b'\x00\x00' # force the TCP checksum field to start with zeros
                        #print("TCP header bytes:", tcp_header)

                    packet = IP(ipv4_header) / TCP(tcp_header) / Raw(load=payload)

                    # Calculate the TCP checksum
                    if checksum_tcp:
                        packet_raw = raw(packet)
                        tcp_raw = packet_raw[20:]
                        tcp_chksum = in4_chksum(socket.IPPROTO_TCP, packet[IP], tcp_raw)  # For more infos, call "help(in4_chksum)"
                        #print("TCP Checksum: ", hex(tcp_chksum))
                        packet[TCP].chksum = tcp_chksum

                    packet = Ether(src=ipv4_to_mac_dict[ipv4_src], dst=ipv4_to_mac_dict[ipv4_dst], type=0x800) / packet
                    
                #print("packet len:", len(packet))

                #print(f"Packet: {packet}")  # Debug: Print the constructed packet
                packets.append(packet)
            
            ##############
            ## IPv4/UDP ##
            ##############
            elif protocols == 'ipv4_udp_' or \
                protocols == 'eth_ipv4_udp_' or \
                protocols == 'ipv4_udp_payload_' or \
                protocols == 'eth_ipv4_udp_payload_':

                ########## 
                ## IPv4 ##
                ########## 
                # Concatenate the bits to form a minimal value that is multiple of 8 and create bytes (or bytes) from it.
                # For example: ipv4 version (4 bits) + ipv4 hl (4 bits) sum up to 8. So, gather these fields and create a byte.
                total = create_byte_representation(row, ipv4_prefixes)

                # Concatenate using the `+` operator
                ipv4_header = b''.join(total)

                # Once we have the 'ipv4_header' fields, calculate the checksum for IPv4, but it is optional
                if checksum_ipv4:
                    ipv4_header = compute_ipv4_checksum(ipv4_header)
                    #print("Header with checksum:", ipv4_header)
                
                #########
                ## UDP ##
                #########
                # Concatenate the bits to form a minimal value that is multiple of 8 and create bytes (or bytes) from it.
                total = create_byte_representation(row, udp_prefixes)
                
                # Concatenate using the `+` operator
                udp_header = b''.join(total)
                #print("UDP (concatenated): ", udp_header)

                # payload for IPv4/UDP 
                payload = int(process_field(row, 'ipv4_tl', 16),2) - len(ipv4_header) - len(udp_header)
                payload = b'\x00' * payload
                packet_data = ipv4_header + udp_header + payload

                # Save the unique IPs to create ethernet header
                length_ip = 32

                prefix = 'ipv4_src_'
                ipv4_src = process_field(row, prefix, length_ip)
                ipv4_src = binary_to_ipv4_string(ipv4_src)
                #
                prefix = 'ipv4_dst_'
                ipv4_dst = process_field(row, prefix, length_ip)
                ipv4_dst = binary_to_ipv4_string(ipv4_dst)
                
                # Generate a random unique MAC
                rnd_mac = generate_unique_random_mac(rnd_mac_unique)

                if ipv4_src not in ipv4_to_mac_dict:
                    ipv4_to_mac_dict[ipv4_src] = rnd_mac
                
                # Generate a random unique MAC
                rnd_mac = generate_unique_random_mac(rnd_mac_unique)

                if ipv4_dst not in ipv4_to_mac_dict:
                    ipv4_to_mac_dict[ipv4_dst] = rnd_mac

                # Create packet
                if 'eth_' in protocols:
                    ##############
                    ## Ethernet ##
                    ##############
                    total = create_byte_representation(row, eth_prefixes)
                    eth_header = b''.join(total)
                    packet_data = eth_header + packet_data
                    packet = Raw(load=packet_data)
                else:
                    if checksum_udp:
                        # Set the checksum field to zero (2 bytes) in udp_header
                        udp_header = udp_header[:6] + b'\x00\x00' + udp_header[8:]
                    #packet = Ether(src=ipv4_to_mac_dict[ipv4_src], dst=ipv4_to_mac_dict[ipv4_dst], type=0x800) / Raw(load=packet_data)
                    packet = IP(ipv4_header) / UDP(udp_header) / Raw(load=payload)

                    # Calculate the UDP checksum
                    if checksum_udp:
                        packet_raw = raw(packet)
                        udp_raw = packet_raw[20:]
                        
                        # Calculate the checksum
                        udp_chksum = in4_chksum(socket.IPPROTO_UDP, packet[IP], udp_raw)  # For more infos, call "help(in4_chksum)"
                        #print("UDP Checksum: ", hex(udp_chksum))
                        packet[UDP].chksum = udp_chksum
                    
                    packet = Ether(src=ipv4_to_mac_dict[ipv4_src], dst=ipv4_to_mac_dict[ipv4_dst], type=0x800) / packet
                #print("packet len:", len(packet))

                #print(f"Packet: {packet}")  # Debug: Print the constructed packet
                packets.append(packet)
                
            else:
                raise ValueError(f"Invalid protocol combination: '{protocols}'.")

        except ValueError as e:
            print(f"Error processing packet for row {index}: {e}")
        except Exception as e:
            print(f"Error constructing packet for row {index}: {e}")

    return packets


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Usage of nPrint2PCAP (nPrint->PCAP) converter")
    parser.add_argument('-n', '--nprint', nargs=1, dest='input',
                        help="Specify the name of the nPrint input file.",
                        required=True)
    parser.add_argument('-o', '--output', nargs=1, dest='output',
                        help="Specify the name of the PCAP output file to be generated.",
                        required=True,
                        default="output.pcap")
    parser.add_argument('-4', '--checksum-ipv4', dest='checksum_ipv4',
                        help="Calculate the IPv4 checksum",
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument('-t', '--checksum-tcp', dest='checksum_tcp',
                        help="Calculate the TCP checksum",
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument('-u', '--checksum-udp', dest='checksum_udp',
                        help="Calculate the UDP checksum",
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument('-v', '--verify-nprint', dest='verify_nprint',
                        help="Verify and correct the nPrint input file malformation",
                        action='store_true',
                        required=False,
                        default=False)

    args = parser.parse_args()
    
    input = args.input[0] # input nPrint file
    output = args.output[0] #output PCAP file
    checksum_ipv4 = args.checksum_ipv4
    checksum_tcp = args.checksum_tcp
    checksum_udp = args.checksum_udp
    verify_nprint = args.verify_nprint

    print("{}The following arguments were set:            {}".format(bold,none))
    print("{}Input file:                                  {}{}{}".format(bold,green,input,none))
    print("{}Output file:                                 {}{}{}".format(bold,green,output,none))
    print("{}Calculate checksum for IPv4                  {}{}{}".format(bold,green,checksum_ipv4,none))
    print("{}Calculate checksum for TCP                   {}{}{}".format(bold,green,checksum_tcp,none))
    print("{}Calculate checksum for UDP                   {}{}{}".format(bold,green,checksum_udp,none))
    print("{}Check and correct nPrint file malformation   {}{}{}".format(bold,green,verify_nprint,none))

    # Usage
    packets = csv_to_packets(input)
    #print("packets:", packets)

    # Save packets to PCAP
    with PcapWriter(output, append=True, sync=True) as pcap_writer:
        for pkt in packets:
            #print(f"Writing packet: {pkt}")  # Debug: Print packet being written
            pcap_writer.write(pkt)
    
    print("\n{}{}Completed!".format(bold,green))
