from __future__ import annotations

import pytest
import os

from lib.multihost import KnownTopology
from lib.multihost.roles import IPA, LDAP, Client


@pytest.mark.topology(KnownTopology.IPA)
def test_sssctl_register(client: Client):
    """
    :title: Register a key with sssctl
    :setup:
        1. Setup IDM client with FIDO and umockdev setup
    :steps:
        1. Use sssctl to register a FIDO2 key.
        2. Check umockdev-run that the output contains the user key mapping data.
    :expectedresults:
        1. New key is registered
        2. Output contains key mapping data.
    :customerscenario: False
    """
    hidraw = "/dev/hidraw1"
    tc = "sssctl_reg_test1"
    cmd = "sssctl passkey-exec --register --username=user1 --domain=ldap.test"
    for record_file in ['yk.umockdev', f'{tc}.ioctl', f'{tc}.script', f'{tc}.output']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    urun_command = f"LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/yk.umockdev " \
                   f"--ioctl {hidraw}=/tmp/{tc}.ioctl " \
                   f"--script {hidraw}=/tmp/{tc}.script -- {cmd}"
    output = client.auth.su.umockdev_run(urun_command, 123456)
    output_file = client.fs.read(f"/tmp/{tc}.output").strip()
    assert output.rc == 0 and output.stdout_lines[-1].strip() == output_file


@pytest.mark.topology(KnownTopology.IPA)
def test_sssctl_register_ipa(client: Client, ipa: IPA):
    """
    :title: Register a key with IPA sssctl command
    :setup:
        1. Setup IDM client with FIDO and umockdev setup
    :steps:
        1. Use sssctl to register a FIDO2 key using ipa command.
        2. Check umockdev-run that the output contains the user key mapping data.
    :expectedresults:
        1. New key is registered with IPA command.
        2. Output contains key mapping data.
    :customerscenario: False
    """
    client.host.ssh.run('kinit admin@IPA.TEST', input='Secret123', raise_on_error=False)
    ipa.user('user1').add()
    hidraw = "/dev/hidraw1"
    tc = "sssctl_reg_ipa_test2"
    cmd = "ipa user-add-passkey user1 --register --cose-type=es256 --require-user-verification=True"
    for record_file in ['yk.umockdev', f'{tc}.ioctl', f'{tc}.script', f'{tc}.output']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    urun_command = f"LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/yk.umockdev " \
                   f"--ioctl {hidraw}=/tmp/{tc}.ioctl " \
                   f"--script {hidraw}=/tmp/{tc}.script -- {cmd}"
    output = client.auth.su.umockdev_run(urun_command, 123456)
    output_file = client.fs.read(f"/tmp/{tc}.output").strip()
    assert output.rc == 0 and output.stdout_lines[-1].strip() == output_file


@pytest.mark.topology(KnownTopology.IPA)
def test_su_check_ipa(client: Client, ipa: IPA):
    """
    :title: Check authentication of user with IPA
    :setup:
        1. Add a IPA user with passkey_mapping.
        2. Setup IDM client with FIDO and umockdev setup
        3. Create the recording files when authentications is successful
        4. Add 'pam_passkey_auth = True' under pam section of sssd.conf file.
    :steps:
        1. Check the umockdev-run command for authentication of the user.
        2. Check umockdev-run that the output contains the username.
    :expectedresults:
        1. Command returns 0.
        2. Output contains username of the user.
    :customerscenario: False
    """
    user_add = ipa.user('user1').add()
    passkey_str = "passkey:NUZMRUXIb/W8Ij1GqwCDHSCWxt/SxWxckwtQjLYi/X6Y1qZFB+HI8WO6khzAjzsz248kHbaeAf9qfmqfCky1Jg==," +\
                  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIasAa8ogjPCKXeA4KY3t0W3xBRmG+E4D+MNoRIAJrYuNLSYtAcOL7DCb" \
                  "Ifgc+7c5Y4Mh/FzoEyeumKGYMoyTfg=="
    user_add.passkey_add(passkey_str)
    client.sssd.pam['pam_passkey_auth'] = 'true'
    client.sssd.start()
    tc = "su_ipa_test3"
    for record_file in [f'{tc}.ioctl', f'{tc}.script', f'{tc}.device']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    command_su = f"""LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/{tc}.device """ + \
                 f"""--script /dev/hidraw1=/tmp/{tc}.script --ioctl /dev/hidraw1=/tmp/{tc}.ioctl -- """ + \
                 f"""bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> """ + \
                 f"""/etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - """ +\
                 f"""user1@ipa.test -c whoami"'"""

    client.fs.write('/tmp/runsu_latest.sh', command_su, mode="a+rwx")
    output = client.auth.su.umockdev_su('pushd /tmp; sh runsu_latest.sh', 123456)
    assert output.stdout_lines[-1] == 'user1'


@pytest.mark.topology(KnownTopology.IPA)
def test_su_check_fail_wrong_pin(client: Client, ipa: IPA):
    """
    :title: Check authentication deny when wrong pin is used to authenticate the user for IPA user
    :setup:
        1. Add a IPA user with passkey_mapping.
        2. Setup IDM client with FIDO and umockdev setup
        3. Create the recording files when authentications is failed due to wrong pin
        4. Add 'pam_passkey_auth = True' under pam section of sssd.conf file.
    :steps:
        1. Check the umockdev-run command for authentication of the user.
        2. Check umockdev-run that the output contains the authentication failure message
    :expectedresults:
        1. Command returns 0.
        2. Output contains Authentication failure
    :customerscenario: False
    """
    user_add = ipa.user('user1').add()
    passkey_str = "passkey:NUZMRUXIb/W8Ij1GqwCDHSCWxt/SxWxckwtQjLYi/X6Y1qZFB+HI8WO6khzAjzsz248kHbaeAf9qfmqfCky1Jg==," +\
                  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIasAa8ogjPCKXeA4KY3t0W3xBRmG+E4D+MNoRIAJrYuNLSYtAcOL7DCb" \
                  "Ifgc+7c5Y4Mh/FzoEyeumKGYMoyTfg=="
    user_add.passkey_add(passkey_str)
    client.sssd.pam['pam_passkey_auth'] = 'true'
    client.sssd.start()
    tc = "su_wrong_pin_test4"
    for record_file in [f'{tc}.ioctl', f'{tc}.script', f'{tc}.device']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    command_su = f"""LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/{tc}.device """ + \
                 f"""--script /dev/hidraw1=/tmp/{tc}.script --ioctl /dev/hidraw1=/tmp/{tc}.ioctl -- """ + \
                 f"""bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> """ + \
                 f"""/etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - """ +\
                 f"""user1@ipa.test -c whoami"'"""

    client.fs.write('/tmp/runsu_latest.sh', command_su, mode="a+rwx")
    output = client.auth.su.umockdev_su('pushd /tmp; sh runsu_latest.sh', 67890)
    assert output.stdout_lines[-1] == 'su: Authentication failure'


@pytest.mark.topology(KnownTopology.IPA)
def test_su_check_fail_wrong_passkey_string(client: Client, ipa: IPA):
    """
    :title: Check authentication deny when wrong passkey mapping is used while adding the user in IPA server
    :setup:
        1. Add a IPA user with passkey_mapping.
        2. Setup IDM client with FIDO and umockdev setup
        3. Create the recording files when authentications is failed due to wrong passkey mapping was added
        4. Add 'pam_passkey_auth = True' under pam section of sssd.conf file.
    :steps:
        1. Check the umockdev-run command for authentication of the user.
        2. Check umockdev-run that the output contains the authentication failure message
    :expectedresults:
        1. Command returns 0.
        2. Output contains Authentication failure
    :customerscenario: False
    """
    user_add = ipa.user('user1').add()
    passkey_str = "passkey:oducA9WSTrzBHX2gUKylRNl2PD2XCb4a7V0XJOtahqIX7wGcAugflvrVjbWG2JPTsLlVf+j/dmia7SNIVhK5AA==," +\
                  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGEa7EktmUw4AOR6Y6r1W2zxXptQh3YaDNdvQEifZ3NpgRosVv+GS85uR3h6Ed" +\
                  "1E7FtgfugwsZYeR8+9+GM6h8g=="
    user_add.passkey_add(passkey_str)
    client.sssd.pam['pam_passkey_auth'] = 'true'
    client.sssd.start()
    tc = "su_wrong_passkey_str_test5"
    for record_file in [f'{tc}.ioctl', f'{tc}.script', f'{tc}.device']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    command_su = f"""LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/{tc}.device """ + \
                 f"""--script /dev/hidraw1=/tmp/{tc}.script --ioctl /dev/hidraw1=/tmp/{tc}.ioctl -- """ + \
                 f"""bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> """ + \
                 f"""/etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - """ +\
                 f"""user1@ipa.test -c whoami"'"""

    client.fs.write('/tmp/runsu_latest.sh', command_su, mode="a+rwx")
    output = client.auth.su.umockdev_su('pushd /tmp; sh runsu_latest.sh', 123456)
    assert output.stdout_lines[-1] == 'su: Authentication failure'


@pytest.mark.topology(KnownTopology.LDAP)
def test_su_check_for_ldap(client: Client, ldap: LDAP):
    """
    :title: Check authentication of user with LDAP
    :setup:
        1. Add a LDAP user with passkey_mapping.
        2. Setup IDM client with FIDO and umockdev setup
        3. Create the recording files when authentications is successful
        4. Add 'pam_passkey_auth = True' under pam section of sssd.conf file.
    :steps:
        1. Check the umockdev-run command for authentication of the user.
        2. Check umockdev-run that the output contains the username.
    :expectedresults:
        1. Command returns 0.
        2. Output contains username of the user.
    :customerscenario: False
    """
    passkey_str = "passkey:mQEUTWdtDJPELQNTDdxXNHlfIO1qXFf0LVZjWEfyDALFzvLZ4e4XD5bemqq+o3ThrzT6k1I1n3Z2N00G" \
                  "vLSmjQ==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqk7K5VAI7Evr4ar8X82L/sxm/Bnm5Ti31xnLfGO0BipwH" \
                  "ucw8+/wT4+6T9j5gdMwZKUcXR4BILpmULEyrcZUfw=="
    ldap.user('user1').add(passkey=passkey_str)
    client.sssd.pam['pam_passkey_auth'] = 'true'
    client.sssd.start()
    tc = "su_ldap_test6"
    for record_file in [f'{tc}.ioctl', f'{tc}.script', f'{tc}.device']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    command_su = f"""LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/{tc}.device """ + \
                 f"""--script /dev/hidraw1=/tmp/{tc}.script --ioctl /dev/hidraw1=/tmp/{tc}.ioctl -- """ + \
                 f"""bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> """ + \
                 f"""/etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - """ +\
                 f"""user1@test -c whoami"'"""

    client.fs.write('/tmp/runsu_latest.sh', command_su, mode="a+rwx")
    output = client.auth.su.umockdev_su('pushd /tmp; sh runsu_latest.sh', 123456)
    assert output.stdout_lines[-1] == 'user1'


@pytest.mark.topology(KnownTopology.LDAP)
def test_su_check_for_ldap_with_wrong_pin(client: Client, ldap: LDAP):
    """
    :title: Check authentication deny when wrong pin is used to authenticate the user for LDAP user
    :setup:
        1. Add a LDAP user with passkey_mapping.
        2. Setup IDM client with FIDO and umockdev setup
        3. Create the recording files when authentications is failed due to wrong pin
        4. Add 'pam_passkey_auth = True' under pam section of sssd.conf file.
    :steps:
        1. Check the umockdev-run command for authentication of the user.
        2. Check umockdev-run that the output contains the authentication failure message
    :expectedresults:
        1. Command returns 0.
        2. Output contains Authentication failure
    :customerscenario: False
    """
    passkey_str = "passkey:mQEUTWdtDJPELQNTDdxXNHlfIO1qXFf0LVZjWEfyDALFzvLZ4e4XD5bemqq+o3ThrzT6k1I1n3Z2N00G" \
                  "vLSmjQ==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqk7K5VAI7Evr4ar8X82L/sxm/Bnm5Ti31xnLfGO0BipwH" \
                  "ucw8+/wT4+6T9j5gdMwZKUcXR4BILpmULEyrcZUfw=="
    ldap.user('user1').add(passkey=passkey_str)
    client.sssd.pam['pam_passkey_auth'] = 'true'
    client.sssd.start()
    tc = "su_ldap_wrong_pin_test7"
    for record_file in [f'{tc}.ioctl', f'{tc}.script', f'{tc}.device']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    command_su = f"""LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/{tc}.device """ + \
                 f"""--script /dev/hidraw1=/tmp/{tc}.script --ioctl /dev/hidraw1=/tmp/{tc}.ioctl -- """ + \
                 f"""bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> """ + \
                 f"""/etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - """ +\
                 f"""user1@test -c whoami"'"""

    client.fs.write('/tmp/runsu_latest.sh', command_su, mode="a+rwx")
    output = client.auth.su.umockdev_su('pushd /tmp; sh runsu_latest.sh', 67890)
    assert output.stdout_lines[-1] == 'su: Authentication failure'


@pytest.mark.topology(KnownTopology.LDAP)
def test_su_check_for_ldap_with_wrong_passkey_mapping(client: Client, ldap: LDAP):
    """
    :title: Check authentication deny when wrong passkey mapping is used while adding the user in LDAP server
    :setup:
        1. Add a LDAP user with passkey_mapping.
        2. Setup IDM client with FIDO and umockdev setup
        3. Create the recording files when authentications is failed due to wrong passkey mapping was added
        4. Add 'pam_passkey_auth = True' under pam section of sssd.conf file.
    :steps:
        1. Check the umockdev-run command for authentication of the user.
        2. Check umockdev-run that the output contains the authentication failure message
    :expectedresults:
        1. Command returns 0.
        2. Output contains Authentication failure
    :customerscenario: False
    """
    passkey_str = "passkey:aEgemlnC6a/WOoEZ8qU1YMwsTW9+uwmMsJnrgOXwTID0qIBHirzHp6d+e1d3WBhcSf7t9Ji8fl3AdSPtlb" \
                  "dN5Q==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENwDQHwyZmnYaUEp0UNqqnw0tGOGnqOMBGdds6O3+JKbmmJGT" \
                  "n0vo7sKNNcDWDsFhJFU/RLWXmHXglxSo+yw9iQ=="
    ldap.user('user1').add(passkey=passkey_str)
    client.sssd.pam['pam_passkey_auth'] = 'true'
    client.sssd.start()
    tc = "su_ldap_wrong_passkey_str_test8"
    for record_file in [f'{tc}.ioctl', f'{tc}.script', f'{tc}.device']:
        src_file = f"{os.getcwd()}/data/passkey/{tc}/{record_file}"
        client.fs.upload(src_file, f"/tmp/{record_file}")
    command_su = f"""LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/{tc}.device """ + \
                 f"""--script /dev/hidraw1=/tmp/{tc}.script --ioctl /dev/hidraw1=/tmp/{tc}.ioctl -- """ + \
                 f"""bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> """ + \
                 f"""/etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - """ +\
                 f"""user1@test -c whoami"'"""

    client.fs.write('/tmp/runsu_latest.sh', command_su, mode="a+rwx")
    output = client.auth.su.umockdev_su('pushd /tmp; sh runsu_latest.sh', 123456)
    assert output.stdout_lines[-1] == 'su: Authentication failure'

