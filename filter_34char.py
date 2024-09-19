import argparse
import re

def filter_34char_addresses(input_file, output_file):
    # Regex pattern to match strings with 34 characters after the first space
    pattern = re.compile(r'\b(\S{34})\b')
    
    with open(input_file, 'r') as infile:
        lines = infile.readlines()
    
    # Filter lines with exactly 34 characters after the first space
    filtered_strings = []
    for line in lines:
        match = pattern.search(line)
        if match:
            filtered_strings.append(match.group(1))
    
    # Write the filtered results to output file
    with open(output_file, 'w') as outfile:
        for string in filtered_strings:
            outfile.write(string + '\n')

    print(f"Filtered {len(filtered_strings)} addresses with 34 characters and saved to {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter addresses with exactly 34 characters after the first space")
    parser.add_argument('--input', type=str, required=True, help="Input file containing addresses")
    parser.add_argument('--output', type=str, required=True, help="Output file to save filtered addresses")
    
    args = parser.parse_args()
    
    filter_34char_addresses(args.input, args.output)
