"""A set of utility functions for encryption and network operations.
"""
import io
import json
import logging
import os
import re
import socket
import sys
import time
import typing

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import PIL
import requests
import websockets

import secret_pixel

log = logging.getLogger(__name__)

_HOST_IP_ADDRESS = None
GLOBAL_BYTE_ORDER = 'big'
_PUBLIC_EXPONENT = 0x10001
RSA_BIT_STRENGTH = 2048
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'


def _benchmark_icon(public_key: rsa.RSAPublicKey, icon: typing.Dict):
    """Performs a binary search of the capacity of an encrypted payload in bytes.

    Parameters
    ----------
    public_key : rsa.RSAPublicKey
        The public key to use
    icon : typing.Dict
        The icon dictionary

    Returns
    -------
    int
        The number of bytes that can be encoded in the image
    """
    gen_byte_string = lambda x : os.urandom(x) # pylint: disable=W0108,C3001
    icon_bytes = icon.get('content')
    if not icon_bytes:
        return 0

    capacity = 1
    increment = 1
    overflow = False
    while True:
        try:
            data = os.urandom(capacity)
            secret_pixel.encode_bytes(icon_bytes, data, public_key)
        except OverflowError:
            if increment == 1:
                capacity = capacity - 1
                break
            else:
                increment //= 2
                capacity -= increment
                overflow = True
        else:
            if overflow and increment == 1:
                break
            capacity += increment
            if not overflow:
                increment *= 2
    try:
        data = os.urandom(capacity)
        secret_pixel.encode_bytes(icon_bytes, data, public_key)
        return capacity
    except:
        raise Exception("Not sure what happened here.")


def benchmark_icons(public_key: rsa.RSAPublicKey, icons: typing.Dict):
    """Benchmarks icons to determine their maximum capacity

    Parameters
    ----------
    public_key : rsa.RSAPublicKey
        The public key to use
    icons : typing.Dict
        A dictionary of path -> icon reponse

    Returns
    -------
    typing.Dict
        The dict of icons with the '_capacity' key set to the capacity in bytes.
    """
    benchmarked_icons = {}
    for icon_path, icon in icons.items():
        capacity = _benchmark_icon(public_key, icon)
        icon['_capacity'] = capacity
        benchmarked_icons[icon_path] = icon
    return benchmarked_icons


def generate_rsa():
    """Generates a random RSA private key.

    Returns
    -------
    rsa.RSAPrivateKey
        The private key generated.
    """
    return rsa.generate_private_key(
        public_exponent=_PUBLIC_EXPONENT,
        key_size=RSA_BIT_STRENGTH,
        backend=default_backend()
    )


def filter_icon_list(
        location: str,
        icons: typing.List[typing.Dict]
    ):
    """Filters a list of icons by getting them from the target device

    Parameters
    ----------
    location : str
        SSDP reported location
    icons : typing.List[typing.Dict]
        UPNP icons as dict representations

    Returns
    -------
    typing.Dict
        A dictionary of image path -> Response cache of the icon
    """
    images = {}
    # These are pulled from xmltodict which either is a list or a single value
    if isinstance(icons, dict):
        icons = [icons]
    for icon in icons:
        icon_path = icon.get('url')
        if icon_path and isinstance(icon_path, str):
            try:
                icon_url = location + icon_path
                print(f"Fetching icon {icon_url}")
                response = requests.get(icon_url, timeout=10)
                response.raise_for_status()
                # Try opening it with Pillow to ensure we can use it
                # Pillow will choke on images encoded with secret_pixel
                _ = PIL.Image.open(io.BytesIO(response.content))
                images[icon_path] = {
                    'content': response.content,
                    'status': response.status_code,
                    'headers': response.headers
                }
            except requests.exceptions.HTTPError:
                pass
            except PIL.UnidentifiedImageError:
                # This is probably from another agent, skip it
                pass
            except Exception as e:  # pylint: disable=W0718
                log.error(
                    "Exception fetching icon %s", e, exc_info=sys.exc_info
                )
    return images


def get_host_ip_address():
    """Gets the host IP address

    Returns
    -------
    str
        Host IP address
    """
    global _HOST_IP_ADDRESS # pylint: disable=W0603
    while _HOST_IP_ADDRESS is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 1337))
            _HOST_IP_ADDRESS = sock.getsockname()[0]
        except socket.error:
            _HOST_IP_ADDRESS = None
        finally:
            sock.close()
        time.sleep(1)

    return _HOST_IP_ADDRESS


def replace_ip(input_string: str):
    """Replaces an IP address in the input_string with the host IP address

    Parameters
    ----------
    input_string : str
        The string to replace IPs in

    Returns
    -------
    str
        The string with the IP addresses replaced
    """
    result = re.sub(IP_PATTERN, get_host_ip_address(), input_string)
    return result


def extract_ip_port(url):
    # Regular expression to match IP address and optional port
    pattern = r'http(?:s)?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?'
    
    match = re.match(pattern, url)
    if match:
        ip = match.group(1)
        port = match.group(2)
        
        if port is None:
            if url.startswith('https://'):
                port = '443'
            else:
                port = '80'
        
        return ip, int(port)
    else:
        raise ValueError("URL format not recognized")


def get_compact_key(key: rsa.RSAPrivateKey | rsa.RSAPublicKey):
    """Provides a compact key that only contains the n value converted to bytes

    Parameters
    ----------
    key : rsa.RSAPrivateKey | rsa.RSAPublicKey
        The a public or private key

    Returns
    -------
    bytes
        The n value as bytes encoded in _N_BYTE_ORDER encoding
    """
    if isinstance(key, rsa.RSAPrivateKey):
        public_numbers = key.public_key().public_numbers()
    else:
        public_numbers = key.public_numbers()
    return public_numbers.n.to_bytes(2048//8, byteorder=GLOBAL_BYTE_ORDER)


def public_key_from_n(n_bytes):
    n = int.from_bytes(n_bytes, byteorder=GLOBAL_BYTE_ORDER)
    try:
        return rsa.RSAPublicNumbers(_PUBLIC_EXPONENT, n).public_key()
    except Exception:  # pylint: disable=W0718
        return None


def load_compact_key(n_bytes: bytes):
    """Loads a public key given an n and using _N_PUBlIC_EXPONENT

    Parameters
    ----------
    n_bytes : bytes
        The bytes of the n value in _N_BYTE_ORDER encoding

    Returns
    -------
    rsa.RSAPublicKey
        The loaded public key.
    """
    n = int.from_bytes(n_bytes, byteorder=GLOBAL_BYTE_ORDER)
    return rsa.RSAPublicNumbers(_PUBLIC_EXPONENT, n).public_key()


if __name__ == "__main__":
    print(get_ssdp_devices())
