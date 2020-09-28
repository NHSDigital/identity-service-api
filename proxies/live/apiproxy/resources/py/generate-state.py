import os
import urllib
import base64

# 32 bytes = 256 bits, well above the RFC recommended 160.
# https://tools.ietf.org/html/rfc6749#section-10.10
random_bytes = os.urandom(32)

# reduce length of token w/ base64 encoding
random_bytes_str = base64.b64encode(random_bytes)

# Make safe to pass around as a query parameter
safe_random_bytes_str = urllib.quote(random_bytes_str, safe='')

flow.setVariable('apigee.state', safe_random_bytes_str)
