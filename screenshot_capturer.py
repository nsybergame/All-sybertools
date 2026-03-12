#!/usr/bin/env python3
"""
SCREENSHOT CAPTURER
===================

Capture screenshots of websites.

DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY.
Respect website terms of service.

Requirements:
    pip install selenium pillow
    Requires Chrome/Firefox driver

Author: CyberSecurity Tools Hub
"""

import argparse
import sys
import os
from datetime import datetime

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

def capture_screenshot(url: str, output: str, browser: str = 'chrome', 
                       width: int = 1920, height: int = 1080, 
                       full_page: bool = False, timeout: int = 30) -> dict:
    """
    Capture screenshot of a website.
    
    Args:
        url: Website URL
        output: Output file path
        browser: Browser to use (chrome/firefox)
        width: Viewport width
        height: Viewport height
        full_page: Capture full page
        timeout: Page load timeout
    
    Returns:
        Dictionary with result info
    """
    result = {
        'url': url,
        'output': output,
        'success': False,
        'error': None
    }
    
    if not SELENIUM_AVAILABLE:
        result['error'] = 'Selenium not installed. Run: pip install selenium'
        return result
    
    driver = None
    
    try:
        # Setup browser
        if browser.lower() == 'chrome':
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument(f'--window-size={width},{height}')
            driver = webdriver.Chrome(options=options)
        else:
            options = FirefoxOptions()
            options.add_argument('--headless')
            options.add_argument(f'--width={width}')
            options.add_argument(f'--height={height}')
            driver = webdriver.Firefox(options=options)
        
        # Load page
        driver.set_page_load_timeout(timeout)
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        driver.get(url)
        
        # Wait for page to load
        driver.implicitly_wait(5)
        
        # Take screenshot
        if full_page:
            # Get total page height
            total_height = driver.execute_script(
                "return document.body.scrollHeight"
            )
            driver.set_window_size(width, total_height)
        
        driver.save_screenshot(output)
        result['success'] = True
        
    except Exception as e:
        result['error'] = str(e)
    
    finally:
        if driver:
            driver.quit()
    
    return result

def capture_with_playwright(url: str, output: str, width: int = 1920, 
                            height: int = 1080, full_page: bool = False) -> dict:
    """Capture using Playwright (alternative to Selenium)."""
    result = {
        'url': url,
        'output': output,
        'success': False,
        'error': None
    }
    
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={'width': width, 'height': height})
            
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            page.goto(url, wait_until='networkidle')
            
            if full_page:
                page.screenshot(path=output, full_page=True)
            else:
                page.screenshot(path=output)
            
            browser.close()
            result['success'] = True
    
    except ImportError:
        result['error'] = 'Playwright not installed. Run: pip install playwright && playwright install'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Screenshot Capturer - Capture website screenshots",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python screenshot_capturer.py https://example.com -o screenshot.png
  python screenshot_capturer.py google.com -o google.png --full-page
  python screenshot_capturer.py https://site.com -o out.png -w 1280 -h 720
        """
    )
    
    parser.add_argument("url", help="URL to capture")
    parser.add_argument("-o", "--output", default="screenshot.png",
                        help="Output file path (default: screenshot.png)")
    parser.add_argument("-b", "--browser", default="chrome",
                        choices=['chrome', 'firefox'],
                        help="Browser to use (default: chrome)")
    parser.add_argument("-w", "--width", type=int, default=1920,
                        help="Viewport width (default: 1920)")
    parser.add_argument("-H", "--height", type=int, default=1080,
                        help="Viewport height (default: 1080)")
    parser.add_argument("--full-page", action="store_true",
                        help="Capture full page")
    parser.add_argument("--playwright", action="store_true",
                        help="Use Playwright instead of Selenium")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Page load timeout in seconds")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  SCREENSHOT CAPTURER - CyberSecurity Tools Hub")
    print("="*70)
    
    try:
        print(f"\n  URL: {args.url}")
        print(f"  Output: {args.output}")
        print(f"  Size: {args.width}x{args.height}")
        if args.full_page:
            print("  Mode: Full page")
        
        print("\n  Capturing screenshot...")
        
        if args.playwright:
            result = capture_with_playwright(
                args.url, args.output, args.width, args.height, args.full_page
            )
        else:
            result = capture_screenshot(
                args.url, args.output, args.browser,
                args.width, args.height, args.full_page, args.timeout
            )
        
        if result['success']:
            print(f"\n  ✓ Screenshot saved to: {args.output}")
            file_size = os.path.getsize(args.output)
            print(f"  File size: {file_size / 1024:.1f} KB")
        else:
            print(f"\n  ✗ Error: {result['error']}")
        
        print("\n" + "="*70)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
