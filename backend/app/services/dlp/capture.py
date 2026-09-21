"""Bounded TCP reassembly and cleartext HTTP object extraction.

No TLS decryption: a stream we cannot read is counted, never assumed clean.
"""
import ipaddress
import re
import zlib
from email import policy
from email.parser import BytesParser
from pathlib import Path

import dpkt

from app.services.dlp.constants import MAX_PACKETS, MAX_STREAM, MAX_STREAMS, MAX_TOTAL


def looks_like_text(data):
    """Cheap guard so binary protocols are not decoded as cleartext payload."""
    sample = data[:8192]
    if not sample or b'\x00' in sample:
        return False
    printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128)
    return printable / len(sample) >= .9


def reassemble(path):
    streams, total = {}, 0
    coverage = {'packet_limit': False, 'byte_limit': False, 'stream_limit': False, 'gaps': 0, 'malformed_packets': 0, 'encrypted_streams': 0}
    with Path(path).open('rb') as handle:
        try:
            reader = dpkt.pcap.Reader(handle)
        except (ValueError, dpkt.NeedData):
            handle.seek(0)
            reader = dpkt.pcapng.Reader(handle)
        linktype = reader.datalink()
        for number, (_, raw) in enumerate(reader):
            if number >= MAX_PACKETS:
                coverage['packet_limit'] = True
                break
            try:
                if linktype == 1:
                    network = dpkt.ethernet.Ethernet(raw).data
                elif linktype == 113:
                    network = dpkt.sll.SLL(raw).data
                elif linktype == 276:
                    # Linux any-interface captures can use cooked capture v2.
                    protocol = int.from_bytes(raw[:2], 'big')
                    if protocol not in (0x0800, 0x86dd):
                        continue
                    network = dpkt.ip6.IP6(raw[20:]) if protocol == 0x86dd else dpkt.ip.IP(raw[20:])
                elif linktype in (101, 228, 229):
                    network = dpkt.ip6.IP6(raw) if raw[0] >> 4 == 6 else dpkt.ip.IP(raw)
                else:
                    coverage['unsupported_linktype'] = linktype
                    break
                tcp = network.data
                if not isinstance(tcp, dpkt.tcp.TCP):
                    continue
                key = (str(ipaddress.ip_address(network.src)), tcp.sport, str(ipaddress.ip_address(network.dst)), tcp.dport)
                if not tcp.data:
                    continue
                if key not in streams and len(streams) >= MAX_STREAMS:
                    coverage['stream_limit'] = True
                    continue
                stream = streams.setdefault(key, {'segments': {}, 'size': 0, 'truncated': False})
                seq = tcp.seq + int(bool(tcp.flags & dpkt.tcp.TH_SYN))
                if seq in stream['segments']:
                    continue  # retransmission; overlaps are handled below
                if stream['size'] + len(tcp.data) > MAX_STREAM or total + len(tcp.data) > MAX_TOTAL:
                    stream['truncated'] = coverage['byte_limit'] = True
                    continue
                stream['segments'][seq] = bytes(tcp.data)
                stream['size'] += len(tcp.data)
                total += len(tcp.data)
            except (ValueError, AttributeError, dpkt.UnpackError, IndexError):
                coverage['malformed_packets'] += 1
    chunks = []
    for key, stream in streams.items():
        data, end = bytearray(), None
        gap = False
        for seq, payload in sorted(stream['segments'].items()):
            if end is not None and seq > end:
                gap = True
                coverage['gaps'] += 1
                # Do not concatenate across an unknown gap and invent a match.
                chunks.append((key, bytes(data), True))
                data = bytearray()
            overlap = max(0, (end or seq) - seq)
            data.extend(payload[overlap:])
            end = max(end or 0, seq + len(payload))
        if data[:2] in (b'\x16\x03', b'\x17\x03'):
            coverage['encrypted_streams'] += 1
            continue
        chunks.append((key, bytes(data), gap or stream['truncated']))
    return chunks, coverage


def dechunk(data):
    out, offset = bytearray(), 0
    while True:
        end = data.find(b'\r\n', offset)
        if end < 0:
            raise ValueError('Incomplete chunk header')
        size = int(data[offset:end].split(b';')[0], 16)
        offset = end + 2
        if size == 0:
            return bytes(out), offset + 2
        if size < 0 or len(out) + size > MAX_STREAM or offset + size + 2 > len(data):
            raise ValueError('Incomplete or oversized chunk')
        out.extend(data[offset:offset + size])
        if data[offset + size:offset + size + 2] != b'\r\n':
            raise ValueError('Invalid chunk terminator')
        offset += size + 2


def http_objects(data):
    offset, results = 0, []
    while offset < len(data) and len(results) < 50:
        head_end = data.find(b'\r\n\r\n', offset)
        if head_end < 0 or head_end - offset > 65536:
            break
        header = data[offset:head_end]
        first = header.split(b'\r\n', 1)[0].decode('latin1')
        if not re.match(r'^(?:GET |POST |PUT |PATCH |DELETE |HEAD |HTTP/1\.[01] )', first):
            break
        message = BytesParser(policy=policy.default).parsebytes(header.split(b'\r\n', 1)[-1] + b'\r\n\r\n')
        start = head_end + 4
        complete = True
        remaining = data[start:]
        try:
            if 'chunked' in message.get('Transfer-Encoding', '').lower():
                body, consumed = dechunk(remaining)
            elif message.get('Content-Length') is not None:
                size = int(message['Content-Length'])
                if size < 0 or size > MAX_STREAM:
                    raise ValueError('Invalid length')
                body, consumed = remaining[:size], min(size, len(remaining))
                complete = len(body) == size
            elif first.startswith('HTTP/'):
                body, consumed = remaining, len(remaining)
                complete = False  # capture may stop before connection-close
            else:
                body, consumed = b'', 0
            if 'gzip' in message.get('Content-Encoding', '').lower():
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = decoder.decompress(body, MAX_STREAM)
                complete = complete and decoder.eof
        except (ValueError, zlib.error):
            body, consumed, complete = remaining[:MAX_STREAM], len(remaining), False
        host = message.get('Host', '')
        parts = first.split(' ')
        uri = parts[1] if not first.startswith('HTTP/') and len(parts) > 1 else ''
        filename = message.get_filename() or (uri.split('?', 1)[0].rsplit('/', 1)[-1] if uri else '') or 'http-body'
        base = {'filename': filename[:255], 'content_type': message.get_content_type(), 'complete': complete,
                'method': parts[0], 'host': host[:255], 'url': ('http://' + host + uri) if host and uri else '', 'body': body}
        if message.get_content_type().startswith('multipart/'):
            mime = BytesParser(policy=policy.default).parsebytes(b'Content-Type: ' + str(message['Content-Type']).encode() + b'\r\n\r\n' + body)
            for part in mime.walk():
                if part.is_multipart():
                    continue
                results.append({**base, 'filename': (part.get_filename() or part.get_param('name', header='content-disposition') or 'form-field')[:255],
                                'is_file': bool(part.get_filename()),
                                'content_type': part.get_content_type(), 'body': (part.get_payload(decode=True) or b'')[:MAX_STREAM]})
                if len(results) >= 50:
                    break
        else:
            results.append(base)
        # Include query strings/headers for token and PII detection without persisting raw headers.
        results.append({**base, 'filename': 'http-headers', 'content_type': 'text/plain', 'body': header, 'is_header': True})
        offset = start + consumed
        if not complete:
            break
    return results
