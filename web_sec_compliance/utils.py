"""
Utility Functions
"""

import requests
from urllib.parse import urlparse


def extract_hostname(url):
    """
    Extract hostname from URL

    Args:
        url: Full URL string

    Returns:
        hostname: Domain name without protocol
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path

        # Remove port if present
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        return hostname
    except:
        # If URL parsing fails, try basic cleanup
        cleaned = url.replace("https://", "").replace("http://", "")
        cleaned = cleaned.split("/")[0]
        cleaned = cleaned.split(":")[0]
        return cleaned


def safe_request(url, method="GET", timeout=10, **kwargs):
    """
    Make a safe HTTP request with error handling

    Args:
        url: Target URL
        method: HTTP method
        timeout: Request timeout in seconds
        **kwargs: Additional arguments for requests

    Returns:
        response: Response object or None if failed
    """
    try:
        response = requests.request(
            method=method,
            url=url,
            timeout=timeout,
            verify=True,
            allow_redirects=True,
            **kwargs,
        )
        return response
    except requests.exceptions.SSLError:
        # Try without SSL verification for self-signed certs
        try:
            response = requests.request(
                method=method,
                url=url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                **kwargs,
            )
            return response
        except:
            return None
    except:
        return None
