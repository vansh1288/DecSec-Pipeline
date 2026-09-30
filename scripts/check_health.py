#!/usr/bin/env python3
"""
DevSecOps Pipeline - Health Check Script
Waits for application health endpoint to become available.
Used by CI pipeline before running DAST scans.
"""

import sys
import time
import argparse
import requests
from typing import Optional


def check_health(url: str, timeout: int = 5) -> bool:
    """
    Check if the health endpoint responds successfully.
    
    Args:
        url: Health endpoint URL
        timeout: Request timeout in seconds
        
    Returns:
        True if healthy (HTTP 200), False otherwise
    """
    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False


def wait_for_health(
    url: str,
    max_wait: int = 60,
    interval: int = 2,
    timeout: int = 5
) -> bool:
    """
    Wait for health endpoint to become available.
    
    Args:
        url: Health endpoint URL
        max_wait: Maximum time to wait in seconds
        interval: Check interval in seconds
        timeout: Request timeout in seconds
        
    Returns:
        True if healthy within max_wait, False otherwise
    """
    start_time = time.time()
    elapsed = 0
    
    print(f"Waiting for health endpoint at {url} (max {max_wait}s)...")
    
    while elapsed < max_wait:
        if check_health(url, timeout):
            print(f"Health check passed after {elapsed:.1f}s")
            return True
        
        time.sleep(interval)
        elapsed = time.time() - start_time
        if elapsed < max_wait:
            print(f"  Still waiting... ({elapsed:.1f}s elapsed)")
    
    print(f"Health check failed after {max_wait}s")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Wait for application health endpoint"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5000/health",
        help="Health endpoint URL (default: http://localhost:5000/health)"
    )
    parser.add_argument(
        "--max-wait",
        type=int,
        default=60,
        help="Maximum wait time in seconds (default: 60)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=2,
        help="Check interval in seconds (default: 2)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)"
    )
    
    args = parser.parse_args()
    
    success = wait_for_health(
        args.url,
        max_wait=args.max_wait,
        interval=args.interval,
        timeout=args.timeout
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()