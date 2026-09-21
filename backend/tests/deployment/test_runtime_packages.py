import hashlib
import io
import tarfile

import pytest

from app.deployment.package import find_package


@pytest.mark.parametrize('arch,machine', [('amd64', 62), ('arm64', 183)])
def test_package_contains_executable_runtime_for_the_declared_cpu(arch, machine):
    package = find_package(arch)
    metadata = package['manifest']['runtime']
    assert metadata['self_contained'] is True
    assert metadata['arch'] == arch
    with tarfile.open(package['artifact']) as outer:
        data = outer.extractfile('runtime.tar.gz').read()
        assert hashlib.sha256(data).hexdigest() == metadata['sha256']
        assert outer.getmember('run-probe.sh').mode & 0o111
    with tarfile.open(fileobj=io.BytesIO(data)) as runtime:
        for name in ('runtime/lib/ld.so', 'runtime/python/bin/python3.11',
                     'runtime/bin/dumpcap.elf', 'runtime/bin/tcpdump.elf'):
            member = runtime.getmember(name)
            assert member.mode & 0o111
            header = runtime.extractfile(member).read(20)
            assert header[:4] == b'\x7fELF'
            assert int.from_bytes(header[18:20], 'little') == machine
        assert runtime.getmember('runtime/ca-certificates.crt').size > 1000
    assert {'requests', 'psutil', 'regex', 'openpyxl'} <= set(metadata['python_packages'])
