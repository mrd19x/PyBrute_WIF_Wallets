import argparse
import re

def filter_64_char_strings(input_file, output_file):
    """
    Filters unique strings within quotes that have exactly 64 characters from the input file 
    and saves the result to the output file, avoiding duplicates.
    
    :param input_file: Path to the input file
    :param output_file: Path to the output file
    """
    # Regular expression to match strings within double quotes and 64 characters in length
    pattern = re.compile(r'"([a-fA-F0-9]{64})"')
    
    # Set to store unique strings (avoid duplicates)
    unique_strings = set()

    # Read the input file and process each line
    with open(input_file, 'r') as infile:
        for line in infile:
            # Find all matches in the line that are 64 characters long
            matches = pattern.findall(line)
            for match in matches:
                unique_strings.add(match)  # Add to set (automatically removes duplicates)

    # Write the unique strings to the output file
    with open(output_file, 'w') as outfile:
        for unique_string in unique_strings:
            outfile.write(unique_string + '\n')

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Filter unique 64-character strings from input file within double quotes")
    parser.add_argument('--input', type=str, required=True, help="Input file path")
    parser.add_argument('--output', type=str, required=True, help="Output file path")
    
    # Parse command line arguments
    args = parser.parse_args()

    # Filter the lines and save to output
    filter_64_char_strings(args.input, args.output)
    print(f"Filtered unique data has been saved to {args.output}")

if __name__ == "__main__":
    main()
