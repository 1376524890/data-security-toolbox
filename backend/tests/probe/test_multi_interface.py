import socket
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[3]))
import probe.probe as probe


def test_linux_all_interfaces_includes_hotplug(monkeypatch):
    monkeypatch.setattr(probe.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(probe.shutil, 'which', lambda name: '/usr/bin/' + name)
    config = probe.Config(Path('/missing.toml'))
    command = probe.capture_command(config, Path('/tmp/test.partial'))[2]
    assert command[command.index('-i') + 1] == 'any'


def test_dumpcap_explicit_multiple_interfaces(monkeypatch):
    monkeypatch.setattr(probe.shutil, 'which', lambda name: '/usr/bin/' + name)
    config = probe.Config(Path('/missing.toml'))
    config.capture['interface'] = ['ens18', 'ens19']
    command = probe.capture_command(config, Path('/tmp/test.partial'))[2]
    assert command[1:5] == ['-i', 'ens18', '-i', 'ens19']


def test_inventory_contains_ipv6_and_down_nics(monkeypatch):
    monkeypatch.setattr(probe, 'psutil', SimpleNamespace(
        net_if_stats=lambda: {'eth0': SimpleNamespace(isup=True), 'eth1': SimpleNamespace(isup=False)},
        net_if_addrs=lambda: {'eth0': [SimpleNamespace(family=socket.AF_INET, address='10.0.0.2', netmask='255.255.255.0')],
                             'eth1': [SimpleNamespace(family=socket.AF_INET6, address='fe80::1', netmask='ffff::')]}))
    inventory = probe.network_interfaces()
    assert len(inventory) == 2
    assert inventory[1]['addresses'][0]['family'] == 'IPv6'
    assert not inventory[1]['is_up']
