"""Strict webhook and input policies shared by CLI, API and delivery."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit


def webhook_url(url, allow=(), resolve=False):
    if url in allow:
        return url
    try:
        p = urlsplit(url)
        host = p.hostname
        port = p.port or 443
        if p.scheme != 'https' or not host or p.username or p.password or p.fragment:
            raise ValueError('HTTPS public webhook required')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError('Literal IP forbidden')
        host = host.rstrip('.').lower()
        if '.' not in host or host.endswith(('.localhost', '.local', '.internal')):
            raise ValueError('Public hostname required')
        if resolve:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                raise ValueError('Nonpublic destination forbidden')
            address = addresses[0][4][0]
            authority = ('[' + address + ']') if ':' in address else address
            return p._replace(netloc=authority + (':' + str(port) if port != 443 else '')).geturl()
        return url
    except (TypeError, OSError) as e:
        raise ValueError('Invalid webhook destination') from e


def safe_pattern(pattern):
    # One atom (literal or character class), optionally bounded. A single
    # quantified atom avoids exponential ambiguity between adjacent repeats.
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 64:
        raise ValueError('Invalid regex length')
    if '|' in pattern:
        for branch in pattern.split('|'):
            safe_pattern(branch)
        return
    atom = r'(?:[A-Za-z0-9_-]|\[(?:[A-Za-z0-9]|[A-Za-z0-9]-[A-Za-z0-9])+\])'
    if not re.fullmatch(atom + r'(?:\{[0-9]{1,3}(?:,[0-9]{1,3})?\})?', pattern):
        raise ValueError('Only one literal/class with bounded repetition is allowed')
    numbers = re.findall(r'\d+', pattern[pattern.find('{'):]) if '{' in pattern else []
    if numbers and (min(map(int, numbers)) < 1 or max(map(int, numbers)) > 128):
        raise ValueError('Regex repetition out of bounds')
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError('Invalid regex') from e


def csv_cell(value):
    return "'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@', '\t', '\r')) else value


class BodyLimit:
    def __init__(self, app, limit=65536):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > self.limit:
                await send({'type': 'http.response.start', 'status': 413, 'headers': []})
                await send({'type': 'http.response.body', 'body': b'Request body too large'})
                return
            chunks.append(message)
            if not message.get('more_body', False):
                break
        async def replay():
            return chunks.pop(0) if chunks else await receive()
        await self.app(scope, replay, send)
