import struct
import base64

NUM_RANDOM_LONG_INTS = {{ NUM_RANDOM_LONG_INTS_FOR_STATE }}

# Ancient python 2.5 has no handy string-to-binary representation, so
# we convert to a hex string and finish the job ourselves.
HEX_TO_BIN = {
    '0': '0000', '1': '0001', '2': '0010', '3': '0011',
    '4': '0100', '5': '0101', '6': '0110', '7': '0111',
    '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
    'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'
}


def int_to_bin_str(int_):
    # Pad to 64 bits in case leading 4 bits are 0.
    return "".join(HEX_TO_BIN[v] for v in "%x" % int_).zfill(64)


# Grab Apigee's randomLong() generated values.
random_ints = [
    int(flow.getVariable("private.randomLong%d" % i))
    for i in xrange(NUM_RANDOM_LONG_INTS)
]

# Some experimentation reveals that Apigee's randomLong() returns a 64
# bit random number with only the first 54 bits containing random
# data.
random_very_long_binary_str = "".join(int_to_bin_str(int_)[:54] for int_ in random_ints)

# Convert to base64 for shorter, more human readable output by shoving
# actual bytes into a string (since this is python 2.5, we need to use
# struct.pack instead of bytearray).
random_very_long_bytes = "".join(
    struct.pack("B", int(random_very_long_binary_str[i:i+8], 2))
    for i in xrange(0, len(random_very_long_binary_str), 8)
)
random_very_long_b64 = base64.urlsafe_b64encode(random_very_long_bytes)

# Finally, 54*4 = 216 bits of randomness in a mere 36 url-safe, ascii
# characters.

flow.setVariable("apigee.state", random_very_long_b64)