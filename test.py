import pandas as pd
import numpy as np
import time

# Create a sample DataFrame
data = {
    'col1': np.random.randint(1, 10, 10000),
    'col2': np.random.choice(['A', 'B', 'C', 'D', 'E'], 10000),
    'col3': np.random.random(10000) * 100  # Random float values
}

df = pd.DataFrame(data)

# Measure time for iterrows()
start_time = time.time()
for idx, row in df.iterrows():
    value1 = row['col1']
    value2 = row['col2']
end_time = time.time()
iterrows_time = end_time - start_time
print(f"Time taken by iterrows: {iterrows_time:.4f} seconds")

# Measure time for itertuples()
start_time = time.time()
for row in df.itertuples(index=False):
    value1 = row.col1
    value2 = row.col2
end_time = time.time()
itertuples_time = end_time - start_time
print(f"Time taken by itertuples: {itertuples_time:.4f} seconds")
