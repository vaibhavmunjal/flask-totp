import hmac
import time
import random
import string
import struct
import base64
import hashlib
from urllib import parse

import config


def get_totp(secret):
    """Generate TOTP with counter (time) and secret

    - Convert secret into Base32
    - Set Counter time Limit with TOTP_INTERVAL_LIMIT if not provided
    - Generate HMAC(hotp) digest with conter and secret
    - A Long hash is generate, truncate the hash as:
    - Get 19th place from hash & 15 (0Xf)
    - hash_idx = hash[19th] & 0xf
    - truncated_hash = hash[hash_idx:hash_idx+4] & 0x7f
    - token = truncated_hash % 10 ** token_length

    """
    algorithm = hashlib.sha1
    try:
        secret_base = base64.b32decode(secret, True)
        counter = int(time.time()) // config.TOTP_INTERVAL_LIMIT
    except TypeError as e:
        raise e
    counter = struct.pack(">Q", counter)
    hash = hmac.new(secret_base, counter, algorithm).digest()
    hash_idx = hash[19] & 15
    truncated_hash = struct.unpack(">I", hash[hash_idx : hash_idx + 4])[0] & 0x7FFFFFFF
    token = truncated_hash % (10 ** config.TOTP_LENGTH)
    return token


def generate_secret(size=128):
    """
    Generate random ASCII string of length equal to size
    """
    secret = "".join(
        random.SystemRandom().choice(string.ascii_uppercase) for _ in range(size)
    )
    return secret


def get_totp_url(user, secret):
    totp_url = f"otpauth://totp/{config.APPLICATION_HOST}:{user}?"
    totp_dict = {
        "secret": secret,
        "issuer": config.APPLICATION_HOST,
        "algorithm": config.TOTP_ALGORITHM,
        "digits": config.TOTP_LENGTH,
        "period": config.TOTP_INTERVAL_LIMIT,
        "image": config.TOTP_IMAGE,
    }
    totp_url += parse.urlencode(totp_dict, quote_via=parse.quote_plus)
    return totp_url
