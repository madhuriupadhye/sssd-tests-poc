from __future__ import annotations

import pytest

from lib.multihost import KnownTopology, KnownTopologyGroup, Multihost, Topology, TopologyDomain
from lib.multihost.roles import AD, IPA, LDAP, Client, GenericADProvider, GenericProvider, Samba


@pytest.mark.topology('client', Topology(TopologyDomain('sssd', client=1)))
def test_mh(mh: Multihost):
    assert mh.sssd.client[0].role == 'client'


@pytest.mark.topology('client', Topology(TopologyDomain('sssd', client=1)), client='sssd.client[0]')
def test_fixture_name(client: Client):
    assert client.role == 'client'


@pytest.mark.topology(KnownTopology.Client)
def test_client(client: Client):
    assert client.role == 'client'


@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap(client: Client, ldap: LDAP):
    assert client.role == 'client'
    assert ldap.role == 'ldap'


@pytest.mark.topology(KnownTopology.IPA)
def test_ipa(client: Client, ipa: IPA):
    assert client.role == 'client'
    assert ipa.role == 'ipa'


@pytest.mark.topology(KnownTopology.AD)
def test_ad(client: Client, ad: AD):
    assert client.role == 'client'
    assert ad.role == 'ad'


@pytest.mark.topology(KnownTopology.Samba)
def test_samba(client: Client, samba: Samba):
    assert client.role == 'client'
    assert samba.role == 'samba'


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_any_ad(client: Client, provider: GenericADProvider):
    assert True


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_generic_provider(client: Client, provider: GenericProvider):
    assert True


@pytest.mark.parametrize('test', [1, 2])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_parametrize(client: Client, provider: GenericProvider, test: int):
    assert test == 1 or test == 2


@pytest.mark.topology(
    'ldap', Topology(TopologyDomain('sssd', client=1, ldap=1)),
    client='sssd.client[0]', ldap='sssd.ldap[0]'
)
def test_ldap_id__explicit_domain(client: Client, ldap: LDAP):
    ldap.user('user-1').add(uid=10001, gid=10001, password='Secret123')

    client.sssd.import_domain('test', ldap)
    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.config_apply()
    client.sssd.start(apply_config=False)

    result = client.tools.id('user-1@test')
    assert result is not None
    assert result.user.name == 'user-1@test'


@pytest.mark.topology(
    'ldap', Topology(TopologyDomain('sssd', client=1, ldap=1)), dict(test='sssd.ldap[0]'),
    client='sssd.client[0]', ldap='sssd.ldap[0]'
)
def test_ldap_id__implicit_domain(client: Client, ldap: LDAP):
    ldap.user('user-1').add(uid=10001, gid=10001, password='Secret123')

    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.start()

    result = client.tools.id('user-1@test')
    assert result is not None
    assert result.user.name == 'user-1@test'


@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap_id(client: Client, ldap: LDAP):
    # Create organizational units
    ou_users = ldap.ou('users').add()
    ou_groups = ldap.ou('groups').add()

    # Create user
    user = ldap.user('user-1', basedn=ou_users).add(uid=10001, gid=10001, password='Secret123')

    # Create group
    group = ldap.group('group-1', basedn=ou_groups, rfc2307bis=True).add(gid=20001)
    group.add_member(user)

    client.sssd.domain['ldap_schema'] = 'rfc2307bis'
    client.sssd.start()

    result = client.tools.id('user-1')
    assert result is not None
    assert result.user.name == 'user-1'
    assert result.user.id == 10001
    assert result.group.id == 10001
    assert result.group.name is None
    assert result.memberof('group-1')

    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.restart()

    result = client.tools.id('user-1')
    assert result is None

    result = client.tools.id('user-1@test')
    assert result is not None
    assert result.user.name == 'user-1@test'
    assert result.user.id == 10001
    assert result.group.id == 10001
    assert result.group.name is None
    assert result.memberof('group-1@test')


@pytest.mark.topology(KnownTopology.IPA)
def test_ipa_id(client: Client, ipa: IPA):
    # Create user
    user = ipa.user('user-1').add(password='Secret123')

    # Create group
    group = ipa.group('group-1').add()
    group.add_member(user)

    client.sssd.start()

    result = client.tools.id('user-1')
    assert result is not None
    assert result.user.name == 'user-1'
    assert result.user.id == result.group.id
    assert result.user.name == result.group.name
    assert result.memberof('group-1')

    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.restart()

    result = client.tools.id('user-1')
    assert result is None

    result = client.tools.id('user-1@test')
    assert result is not None
    assert result.user.name == 'user-1@test'
    assert result.user.id == result.group.id
    assert result.user.name == result.group.name
    assert result.memberof('group-1@test')


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
def test_generic_id(client: Client, provider: GenericProvider):
    # Create user
    user = provider.user('user-1').add(uid=10001, gid=10001, password='Secret123')

    # Create group
    group = provider.group('group-1').add(gid=20001)
    group.add_member(user)

    client.sssd.start()

    result = client.tools.id('user-1')
    assert result is not None
    assert result.user.name == 'user-1'
    assert result.user.id == 10001
    assert result.group.id == 10001
    assert result.memberof('group-1')

    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.restart()

    result = client.tools.id('user-1')
    assert result is None

    result = client.tools.id('user-1@test')
    assert result is not None
    assert result.user.name == 'user-1@test'
    assert result.user.id == 10001
    assert result.group.id == 10001
    assert result.memberof('group-1@test')


@pytest.mark.topology(KnownTopology.Samba)
def test_samba_id(client: Client, samba: Samba):
    user = samba.user('user-1').add(
        uid=10001, gid=10001, home='/home/test', password='Secret123', gecos='gecos', shell='/bin/sh'
    )
    group = samba.group('group-1').add()
    group.add_member(user)

    user.modify(home='/home/test2')
    user.modify(home=Samba.Flags.DELETE)
    # client.sssd.start()

    # result = client.tools.id('user-1')
    # print(result)
    assert True


@pytest.mark.topology(KnownTopology.AD)
def test_ad_id(client: Client, ad: AD):
    u = ad.user('test-user').add()
    g = ad.group('test').add()
    g.add_member(u)

    assert True


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize('method', ['su', 'ssh'])
def test_auth(client: Client, ldap: LDAP, method: str):
    auth_tool = client.auth.su if method == 'su' else client.auth.ssh
    ldap.user('test').add(password="Secret123")

    client.sssd.start()
    assert auth_tool.password('test', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
def test_sudo(client: Client, provider: LDAP):
    u = provider.user('test').add(password="Secret123")
    provider.sudorule('testrule2').add(user=u, host='ALL', command='/bin/ls')
    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()
    assert client.auth.sudo.list(u.name, 'Secret123')
    assert client.auth.sudo.run('test', 'Secret123', command='/bin/ls')


@pytest.mark.topology(KnownTopology.Samba)
def test_samba_ou(client: Client, samba: Samba):
    print(samba.ldap.naming_context)
    samba.ou('test').add()
    samba.sudorule('testrule').add(user='ALL', host='ALL', command='/bin/ls')


@pytest.mark.topology(KnownTopology.AD)
def test_ad_ou(client: Client, ad: AD):
    ou = ad.ou('sudoers').add()
    u = ad.user('tuser').add()
    r = ad.sudorule('test', ou).add(user=u, host='ALL', command='ALL')
    r.modify(user='ALL', host=ad.Flags.DELETE)
    # ad.sudorule('test', basedn=ou).add(user='ALL', host='ALL', command='ALL')
    # ad.user('tuser').add()

    # client.sssd.start()
    # result = client.tools.id('tuser')
    # assert result.user.name == 'tuser'
