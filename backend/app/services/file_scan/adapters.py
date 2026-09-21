"""Read-only FTP, explicit FTPS and SFTP; bounded listings and downloads."""
import base64
import ftplib
import hashlib
import posixpath
import re
import shlex
import socket
import ssl
import stat
from contextlib import contextmanager

import paramiko


class SourceError(Exception):
    pass


def child_path(parent, name):
    if not name or name in {".", ".."} or any(c in name for c in "/\\\r\n\x00"):
        raise SourceError("invalid_remote_name")
    return posixpath.join(parent, name)


#: LIST fallback for servers that never implemented MLSD (vsftpd 3.0.5 answers
#: 500 and does not advertise it in FEAT). The columns before the name are fixed,
#: so the name is taken as the rest of the line and may contain spaces.
_LIST_ROW = re.compile(
    r"^([-dlbcps])[rwxsStT-]{9}\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\d+\s+[\d:]+\s+(.+)$"
)


def category(exc):
    """A stable label for a transport failure; server text is never echoed."""
    if isinstance(exc, ftplib.error_perm):
        reply = str(exc)
        if reply.startswith("530"):
            return "auth_error"
        if reply.startswith("550"):
            return "path_error"
        return "protocol_error"
    if isinstance(exc, paramiko.AuthenticationException):
        return "auth_error"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, OSError):
        return "unreachable"
    return type(exc).__name__


class PinnedKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        digest = hashlib.sha256(key.asbytes()).digest()
        actual = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
        if not self.expected or actual != self.expected:
            raise SourceError("host_key_mismatch")


@contextmanager
def connect(config, password):
    client = None
    sftp = None
    established = False
    try:
        if config['protocol'] == 'sftp':
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(PinnedKey(config.get('host_key_sha256', '')))
            client.connect(config['host'], port=config['port'], username=config['username'],
                           password=password, timeout=15, banner_timeout=15, auth_timeout=15,
                           look_for_keys=False, allow_agent=False)
            sftp = client.open_sftp()
            sftp.get_channel().settimeout(15)
            established = True
            yield Remote(sftp, True)
        else:
            client = (ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=15)
                      if config['protocol'] == 'ftps' else ftplib.FTP(timeout=15))
            client.connect(config['host'], config['port'])
            client.login(config['username'], password)
            if config['protocol'] == 'ftps':
                client.prot_p()
            client.set_pasv(True)
            established = True
            yield Remote(client, False)
    except SourceError:
        raise
    except Exception as exc:
        if established:
            # Raised by the caller's own work (temp file, parser); not a transport fact.
            raise
        # Server error text may echo a username/password. Keep error categories only.
        raise SourceError(category(exc)) from exc
    finally:
        if sftp is not None:
            sftp.close()
        if client is not None:
            client.close()


class Remote:
    def __init__(self, client, sftp):
        self.client, self.sftp = client, sftp

    def entries(self, path, check, limit=2000):
        if self.sftp:
            for index, item in enumerate(self.client.listdir_iter(path, read_aheads=1)):
                check()
                if index >= limit:
                    raise SourceError('directory_entry_budget')
                kind = ('dir' if stat.S_ISDIR(item.st_mode)
                        else 'file' if stat.S_ISREG(item.st_mode) else 'skip')
                yield child_path(path, item.filename), kind, int(item.st_size or 0)
            return
        try:
            rows = self.mlsd(path, check, limit)
        except ftplib.error_perm as exc:
            # MLSD is optional in RFC 3659; vsftpd 3.0.5 answers 500. Anything else
            # (a 550 for a missing directory, say) is a real answer, not a fallback.
            if str(exc)[:3] not in {'500', '502'}:
                raise SourceError(category(exc)) from exc
            rows = self.unix_list(path, check, limit)
        yield from rows

    def entries_raw(self, path, check, limit=2000):
        """Fallback listing for a directory the SFTP name decoder rejected.

        The SFTP client decodes names strictly as UTF-8, so a single file whose
        name is not valid UTF-8 fails the *entire* listing. Asking the host
        directly (``ls -1a`` over the exec channel) returns bytes we can decode
        ourselves: names that do decode are stat'ed normally, and the undecodable
        ones are reported as ``skip`` — counted and explained, never dropped in
        silence and never presented as content that was read.
        """
        if not self.sftp:
            raise SourceError('protocol_error')
        # Remote wraps an SFTPClient, so the exec channel is opened from its
        # transport rather than from an SSHClient helper.
        session = self.client.get_channel().get_transport().open_session()
        session.settimeout(30)
        session.set_combine_stderr(True)
        session.exec_command('ls -1a -- ' + shlex.quote(path))
        output = b''
        while True:
            chunk = session.recv(65536)
            if not chunk:
                break
            output += chunk
        code = session.recv_exit_status()
        session.close()
        if code != 0:
            raise SourceError('path_error')
        rows = []
        for line in output.split(b'\n'):
            raw = line.rstrip(b'\r')
            if not raw or raw in {b'.', b'..'}:
                continue
            if len(rows) >= limit:
                raise SourceError('directory_entry_budget')
            check()
            try:
                name = raw.decode('utf-8')
            except UnicodeDecodeError:
                rows.append((posixpath.join(path, raw.decode('utf-8', 'replace')), 'skip', 0))
                continue
            child = child_path(path, name)
            try:
                info = self.client.stat(child)
            except OSError:
                rows.append((child, 'skip', 0))
                continue
            mode = info.st_mode or 0
            kind = ('dir' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'skip')
            rows.append((child, kind, int(info.st_size or 0)))
        return rows

    def mlsd(self, path, check, limit):
        rows = []
        def receive(line):
            check()
            if len(rows) >= limit:
                raise SourceError('directory_entry_budget')
            facts, _, name = line.partition(' ')
            values = dict(part.lower().split('=', 1) for part in facts.split(';') if '=' in part)
            kind = values.get('type')
            if kind in {'cdir', 'pdir'}:
                return
            rows.append((child_path(path, name), kind if kind in {'file', 'dir'} else 'skip',
                         int(values.get('size', 0))))
        self.client.retrlines('MLSD ' + path, receive)
        return rows

    def unix_list(self, path, check, limit):
        """Parse ``LIST`` (ls -l) rows: no MLSD facts, but the same entry shapes."""
        rows = []
        def receive(line):
            check()
            if len(rows) >= limit:
                raise SourceError('directory_entry_budget')
            match = _LIST_ROW.match(line.rstrip())
            if not match:
                return  # "total N" headers and device rows carry no usable facts.
            marker, size, name = match.groups()
            if marker == 'l':
                # LIST appends " -> target"; the target is never followed anyway and
                # its slashes must not reach the name validator.
                name = name.split(' -> ', 1)[0]
            kind = 'dir' if marker == 'd' else 'file' if marker == '-' else 'skip'
            rows.append((child_path(path, name), kind, int(size) if kind == 'file' else 0))
        try:
            self.client.retrlines('LIST ' + path, receive)
        except ftplib.error_perm as exc:
            raise SourceError(category(exc)) from exc
        return rows

    def download(self, path, target, consume):
        with target.open('wb') as output:
            def receive(block):
                consume(len(block))
                output.write(block)
            if self.sftp:
                with self.client.open(path, 'rb') as source:
                    while True:
                        block = source.read(65536)
                        if not block:
                            break
                        receive(block)
            else:
                self.client.retrbinary('RETR ' + path, receive, blocksize=65536)
