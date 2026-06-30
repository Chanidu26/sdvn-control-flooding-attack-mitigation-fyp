import sys
import csv
import os

# Write empty result so NS3 can continue
output_file = "./scratch/optimization_link_lifetime_data.csv"
if not os.path.exists(output_file):
    with open(output_file, 'w') as f:
        f.write("link,lifetime\n")

print("optimization_lifetime: skipped (EDCF mode)")
sys.exit(0)
