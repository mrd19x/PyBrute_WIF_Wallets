import argparse
import requests
import time

def check_balances(input_file, output_file):
    with open(input_file, 'r') as infile:
        addresses = [line.strip() for line in infile if line.strip()]

    def get_batches(addresses, batch_size=250):
        """Yield successive batches from addresses."""
        for i in range(0, len(addresses), batch_size):
            yield addresses[i:i + batch_size]
    
    def fetch_balances(addresses):
        """Fetch balances for a batch of addresses."""
        url = "https://blockchain.info/balance?active=" + '|'.join(addresses) + "&cors=true"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to fetch balances: {response.status_code}")
            return {}
    
    results = []
    for batch in get_batches(addresses):
        print(f"Checking batch of {len(batch)} addresses...")
        balances = fetch_balances(batch)
        for address, data in balances.get("balances", {}).items():
            if data['final_balance'] > 0:
                results.append(f"{address}|{data['final_balance'] / 1e8} BTC")  # Convert satoshi to BTC
        
        # Wait for 2 seconds before the next batch
        time.sleep(2)
    
    with open(output_file, 'w') as outfile:
        for result in results:
            outfile.write(result + '\n')

    print(f"Checked {len(addresses)} addresses. Results saved to {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check balances of Bitcoin addresses")
    parser.add_argument('--input', type=str, required=True, help="Input file containing Bitcoin addresses")
    parser.add_argument('--output', type=str, required=True, help="Output file to save addresses with non-zero balance")
    
    args = parser.parse_args()
    
    check_balances(args.input, args.output)
