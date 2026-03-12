#!/usr/bin/env python3
"""
CRYPTO WALLET CHECKER
=====================

Check cryptocurrency wallet addresses and balances.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Only checks public blockchain data.

Requirements:
    pip install requests

Author: CyberSecurity Tools Hub
"""

import requests
import argparse
import sys
import re

# Blockchain API endpoints
API_ENDPOINTS = {
    'bitcoin': {
        'mainnet': 'https://blockchain.info/rawaddr/{address}',
        'balance': 'https://blockchain.info/balance?active={address}',
    },
    'ethereum': {
        'mainnet': 'https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest',
    },
    'litecoin': {
        'mainnet': 'https://api.blockcypher.com/v1/ltc/main/addrs/{address}',
    }
}

def detect_cryptocurrency(address: str) -> str:
    """
    Detect cryptocurrency type from address format.
    
    Args:
        address: Wallet address
    
    Returns:
        Cryptocurrency name
    """
    # Bitcoin addresses
    if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
        return 'bitcoin'
    if re.match(r'^bc1[a-zA-Z0-9]{39,59}$', address):
        return 'bitcoin'  # Bech32
    
    # Ethereum addresses
    if re.match(r'^0x[a-fA-F0-9]{40}$', address):
        return 'ethereum'
    
    # Litecoin addresses
    if re.match(r'^[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
        return 'litecoin'
    if re.match(r'^ltc1[a-zA-Z0-9]{39,59}$', address):
        return 'litecoin'
    
    return 'unknown'

def satoshi_to_btc(satoshi: int) -> float:
    """Convert satoshi to BTC."""
    return satoshi / 100000000

def wei_to_eth(wei: int) -> float:
    """Convert wei to ETH."""
    return wei / 1000000000000000000

def check_bitcoin(address: str) -> dict:
    """Check Bitcoin wallet."""
    result = {
        'address': address,
        'cryptocurrency': 'bitcoin',
        'balance': 0,
        'transactions': 0,
        'total_received': 0,
        'total_sent': 0,
    }
    
    try:
        url = API_ENDPOINTS['bitcoin']['balance'].format(address=address)
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if address in data:
                result['balance'] = satoshi_to_btc(data[address]['final_balance'])
                result['total_received'] = satoshi_to_btc(data[address]['total_received'])
                result['transactions'] = data[address].get('n_tx', 0)
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_ethereum(address: str) -> dict:
    """Check Ethereum wallet."""
    result = {
        'address': address,
        'cryptocurrency': 'ethereum',
        'balance': 0,
        'transactions': 0,
    }
    
    try:
        url = API_ENDPOINTS['ethereum']['mainnet'].format(address=address)
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == '1':
                result['balance'] = wei_to_eth(int(data.get('result', 0)))
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_wallet(address: str) -> dict:
    """
    Check wallet address.
    
    Args:
        address: Wallet address
    
    Returns:
        Dictionary with wallet info
    """
    crypto = detect_cryptocurrency(address)
    
    result = {
        'address': address,
        'cryptocurrency': crypto,
        'valid': crypto != 'unknown',
    }
    
    if crypto == 'bitcoin':
        wallet_data = check_bitcoin(address)
        result.update(wallet_data)
    elif crypto == 'ethereum':
        wallet_data = check_ethereum(address)
        result.update(wallet_data)
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Crypto Wallet Checker - Check wallet addresses and balances",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crypto_wallet_checker.py 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
  python crypto_wallet_checker.py 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
  python crypto_wallet_checker.py --detect 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
        """
    )
    
    parser.add_argument("address", help="Wallet address to check")
    parser.add_argument("--detect", action="store_true",
                        help="Only detect cryptocurrency type")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output as JSON")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  CRYPTO WALLET CHECKER - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        crypto = detect_cryptocurrency(args.address)
        
        print(f"\n  Address: {args.address[:20]}...{args.address[-10:]}")
        print(f"  Cryptocurrency: {crypto.upper()}")
        
        if args.detect:
            print("\n" + "="*70)
            return
        
        if crypto == 'unknown':
            print("\n  [!] Unknown address format")
            sys.exit(1)
        
        print("\n  Fetching wallet data...")
        
        result = check_wallet(args.address)
        
        if 'error' in result:
            print(f"\n  [!] Error: {result['error']}")
        else:
            print(f"\n  Wallet Info:")
            print(f"    Balance: {result.get('balance', 0):.8f} {crypto.upper()}")
            
            if result.get('total_received'):
                print(f"    Total Received: {result['total_received']:.8f} {crypto.upper()}")
            
            if result.get('transactions'):
                print(f"    Transactions: {result['transactions']}")
        
        if args.json:
            print("\n" + json.dumps(result, indent=2))
        
        print("\n" + "="*70)
        print("  Note: Only public blockchain data is accessed.")
        print("="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
