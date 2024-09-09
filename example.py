import pandas as pd

def is_malformed(series):
    """Check if a column contains a malformed sequence of 0, 1, and -1."""
    # Loop through the series to identify patterns like 0, -1, 0 or 1, -1, 1
    for i in range(1, len(series) - 1):
        if series[i] == -1:
            # Check if the previous and next values are the same and are either 0 or 1
            if series[i-1] in [0, 1] and series[i+1] in [0, 1]:
                return True
    return False

# Example usage:
data = {
    'eth_0': [0, -1, 0, -1, 1, -1, 1],
    'ipv4_0': [1, 1, -1, 1, 0, -1, 0],
    'unrelated_column': [5, 6, 7, 8, 9, 10, 11]
}

df = pd.DataFrame(data)

# Columns to monitor
monitor_columns = [col for col in df.columns if any(sub in col for sub in ["eth_", "ipv4_", "udp_", "tcp_", "ipv6_", "Icmp_", "wlan_", "radiotap_"])]

# Check each monitored column
malformed_columns = {col: is_malformed(df[col]) for col in monitor_columns}

# Output the malformed columns
malformed_columns = {k: v for k, v in malformed_columns.items() if v}
print("Malformed Columns:", malformed_columns)
