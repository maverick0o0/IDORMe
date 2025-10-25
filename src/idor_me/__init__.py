"""IDORMe Burp Suite extension core package.

This package contains the logic that powers the IDORMe Burp Suite
extension. The modules are intentionally structured so they can be
imported and exercised from CPython for unit testing while still being
compatible with the Jython runtime shipped with Burp Suite.
"""

__all__ = [
    "Extender",
]
