from __future__ import annotations

import pytest
import re

from lib.multihost import KnownTopology, KnownTopologyGroup
from lib.multihost.roles import AD, IPA, LDAP, Client, GenericADProvider, GenericProvider, Samba


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0001(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: Allow host access
    :id: e62e6258-7bb7-460f-b752-63cf1ec1df42
     """
    ldap.user('testuser1').add(host=client.host.hostname)
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"pycAccess granted for \[{client.host.hostname}\]").search(log_file)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0002(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: Deny host access
    :id: 87efa28d-bb6a-41bb-baf9-a2d9b9da2455
     """
    deny_host = f'{"!"}{client.host.hostname}'
    ldap.user('testuser1').add(host=deny_host)
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert not client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Access denied by \[{deny_host}\]").search(log_file)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0003(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: Host mismatch
    :id: f5faf3ac-fc1b-46e3-8f70-2ef1e906ceef
     """
    mismatch_host = "host2.example.com"
    ldap.user('testuser1').add(host=mismatch_host)
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert not client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"No matching host rule found").search(log_file)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0004(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: access granted to all hosts
    :id: b85ae8d4-1a34-4a88-a66f-61deaf8469da
     """
    ldap.user('testuser1').add(host="*")
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Access granted to all hosts").search(log_file)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0005(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: host attribute missing from user
    :id: 99eae2cd-0638-4e42-a9ce-6fcbc76c63a3
     """
    ldap.user('testuser1').add()
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert not client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Missing hosts. Access denied").search(log_file)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0006(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: hostname is short
    :id: 00d79cea-78d1-43f4-8dde-fac223647877
     """
    client.host.ssh.run('hostname host1', raise_on_error=False)
    ldap.user('testuser1').add(host="host1")
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Access granted for \[host1\]").search(log_file)
    client.host.ssh.run(f'hostname {client.host.hostname}', raise_on_error=False)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0007(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: hostname is case insensitive
    :id: 9f65f517-849a-4621-9187-64d5a49bd9d1
     """
    client.host.ssh.run('hostname host1.example.com', raise_on_error=False)
    ldap.user('testuser1').add(host="HOST1.example.com")
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Access granted for \[HOST1.example.com\]").search(log_file)
    client.host.ssh.run(f'hostname {client.host.hostname}', raise_on_error=False)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0008(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: hostname is case sensitive
    :id: 889f2f7d-15ba-48c6-b179-ad3fac3f5b0f
     """
    client.host.ssh.run('hostname HOST1.example.com', raise_on_error=False)
    ldap.user('testuser1').add(host="host1.example.com")
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Access granted for \[host1.example.com\]").search(log_file)
    client.host.ssh.run(f'hostname {client.host.hostname}', raise_on_error=False)


@pytest.mark.topology(KnownTopology.LDAP)
def test_hbac_0009(client: Client, ldap: LDAP):
    """
    :title: IDM-SSSD-TC: ldap_provider: hbac: non default value of ldap user authorized host
    :id: 550f438a-c126-4836-ba62-97369ac86e21
     """
    ldap.user('testuser1').add(description=client.host.hostname)
    client.sssd.domain['access_provider'] = 'ldap'
    client.sssd.domain['ldap_access_order'] = 'host'
    client.sssd.domain['ldap_user_authorized_host'] = 'description'
    client.sssd.start()
    result = client.tools.id('testuser1')
    assert result.user.name == 'testuser1'
    assert result is not None
    assert client.auth.su.password('testuser1', 'Secret123')
    log_file = client.fs.read("/var/log/sssd/sssd_test.log")
    assert re.compile(f"Option ldap_user_authorized_host has value description").search(log_file)
    assert re.compile(f"Access granted for \[{client.host.hostname}\]").search(log_file)
