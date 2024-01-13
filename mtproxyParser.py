from urllib.parse import urlparse, parse_qs, unquote
import re
import base64
import binascii


def is_hex(s):
    # Check if the string is a valid hexadecimal number
    return re.fullmatch(r'[0-9a-f]*', s or "") is not None


def hex_to_bytes(s):
    # Convert a hexadecimal string to a byte array
    return bytes.fromhex(s)


def no_strict_to_bytes(s):
    return binascii.a2b_base64(__data=s + '=' * (-len(s) % 4), strict_mode=False)


def base64_to_bytes(s):
    try:
        # Convert a base64 string to a byte array
        return base64.b64decode(s + '=' * (-len(s) % 4), validate=False)
    except:
        return no_strict_to_bytes(s)


def urlsafe_base64_to_bytes(s):
    try:
        # Convert a URL-safe base64 string to a byte array
        return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    except:
        return base64_to_bytes(s)


def bytes_to_hex(b):
    # Convert a byte array to a hexadecimal string
    return binascii.hexlify(b).decode()


def initial_parse_secret(secret):
    unquoted = unquote(secret)
    is_urlsafe = True if unquoted != secret else False
    try:
        if is_hex(unquoted):
            raise ValueError
        decoded = urlsafe_base64_to_bytes(unquoted)
        return decoded.hex(), True, is_urlsafe
    except:
        return unquoted, False, is_urlsafe


def parse(url):
    # Parse the URL
    parsed = urlparse(url)
    proto = parsed.scheme
    if not (proto == "tg" or proto == "https"):
        return False, f"Invalid URL protocol: {proto}"

    host_or_path = parsed.netloc if proto == "tg" else parsed.path # keep leading '/'
    if (proto == "tg" and host_or_path != "proxy") or \
       (proto == "https" and host_or_path not in ["/proxy", "/t.me/proxy"]):
        return False, f"Invalid path: {host_or_path}"

    # Parse the query parameters
    query = parse_qs(parsed.query)
    missing = [field for field in ["server", "port", "secret"] if field not in query]
    if missing:
        return False, f"Missing: {missing}"

    raw_secret = query["secret"][0]
    s, is_base_64, is_urlsafe = initial_parse_secret(raw_secret)
    print(raw_secret, s)
    hex_secret, protocol, tls_domain = "", "", ""
    if is_hex(s) and not s.lower().startswith(('ee', 'dd')):
        _type = "Intermediate"
        protocol = "Normal"
        hex_secret = s[0:32]
        s = hex_secret

    elif s.lower().startswith('dd') and is_hex('dd' + s[2:]):
        if s.startswith('DD'):
            s = 'dd' + s[2:]

        _type = "Randomized"
        protocol = "Secure"
        hex_secret = s[-32:]
        s = hex_secret

    elif s.lower().startswith('ee') and is_hex('ee' + s[2:]):
        if s.startswith('EE'):
            s = 'ee' + s[2:]
        _type = "Fake-TLS"
        protocol = "Fake-TLS"
        hex_secret = s[2:34]
        try:
            # Try to decode the domain name as hexadecimal
            tls_domain = "".join(chr(b) for b in hex_to_bytes(s[34:]))
        except:
            # If that fails, try to decode it as URL-safe base64
            tls_domain = urlsafe_base64_to_bytes(s[34:]).decode()
    else:
        return False, f"Invalid secret: {s}"

    if is_base_64:
        protocol += " Base64"
    else:
        protocol += "hex secret"
    if is_urlsafe:
        protocol += ' URL-safe'

    return True, {
        "type": _type,
        "protocol": protocol,
        "server": query["server"][0],
        "port": query["port"][0],
        "secret": hex_secret,
        "raw_secret": s,
        "domain": tls_domain
    }

