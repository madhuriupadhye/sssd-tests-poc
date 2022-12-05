from __future__ import annotations

import configparser
from functools import partial
from io import StringIO
from typing import TYPE_CHECKING

from ..host import MultihostHost, ProviderHost
from ..roles.kdc import KDC
from ..ssh import SSHLog, SSHProcess, SSHProcessResult
from .base import MultihostUtility

if TYPE_CHECKING:
    from ..roles import BaseRole
    from .fs import HostFileSystem
    from .service import HostService


class HostSSSD(MultihostUtility):
    """
    Manage SSSD on remote host.

    All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost, fs: HostFileSystem, svc: HostService, load_config: bool = False) -> None:
        super().__init__(host)
        self.fs = fs
        self.svc = svc
        self.config = configparser.ConfigParser(interpolation=None)
        self.default_domain = None
        self.__load_config = load_config

        self.common: SSSDCommonConfiguration = SSSDCommonConfiguration(self)
        """
        Setup common SSSD configuration.
        """

    def setup(self) -> None:
        """
        Setup SSSD on the host.

        - override systemd unit to disable burst limiting, otherwise we will be
          unable to restart the service frequently
        - reload systemd to apply change to the unit file
        - load configuration from the host (if requested in constructor) or set
          default configuration otherwise

        :meta private:
        """
        # Disable burst limiting to allow often sssd restarts for tests
        self.fs.mkdir('/etc/systemd/system/sssd.service.d')
        self.fs.write('/etc/systemd/system/sssd.service.d/override.conf', '''
            [Unit]
            StartLimitIntervalSec=0
            StartLimitBurst=0
        ''')
        self.svc.reload_daemon()

        if self.__load_config:
            self.config_load()
            return

        # Set default configuration
        self.config.read_string('''
            [sssd]
            config_file_version = 2
            services = nss, pam
        ''')

    def async_start(
        self,
        service='sssd',
        *,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = '0xfff0'
    ) -> SSHProcess:
        """
        Start SSSD service. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: Running SSH process.
        :rtype: SSHProcess
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.async_start(service)

    def start(
        self,
        service='sssd',
        *,
        raise_on_error: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = '0xfff0'
    ) -> SSHProcessResult:
        """
        Start SSSD service. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.start(service, raise_on_error=raise_on_error)

    def async_stop(self, service='sssd') -> SSHProcess:
        """
        Stop SSSD service. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :return: Running SSH process.
        :rtype: SSHProcess
        """
        return self.svc.async_stop(service)

    def stop(self, service='sssd', *, raise_on_error: bool = True) -> SSHProcessResult:
        """
        Stop SSSD service. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :return: SSH process result.
        :rtype: SSHProcess
        """
        return self.svc.stop(service, raise_on_error=raise_on_error)

    def async_restart(
        self,
        service='sssd',
        *,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = '0xfff0'
    ) -> SSHProcess:
        """
        Restart SSSD service. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: Running SSH process.
        :rtype: SSHProcess
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.async_restart(service)

    def restart(
        self,
        service='sssd',
        *,
        raise_on_error: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = '0xfff0'
    ) -> SSHProcessResult:
        """
        Restart SSSD service. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.restart(service, raise_on_error=raise_on_error)

    def clear(self, *, db: bool = True, config: bool = False, logs: bool = False):
        """
        Clear SSSD data.

        :param db: Remove cache and database, defaults to True
        :type db: bool, optional
        :param config: Remove configuration files, defaults to False
        :type config: bool, optional
        :param logs: Remove logs, defaults to False
        :type logs: bool, optional
        """
        cmd = 'rm -fr'

        if db:
            cmd += ' /var/lib/sss/db/*'

        if config:
            cmd += ' /etc/sssd/*.conf /etc/sssd/conf.d/*'

        if logs:
            cmd += ' /var/log/sssd/*'

        self.host.ssh.run(cmd)

    def enable_responder(self, responder: str) -> None:
        """
        Include the responder in the [sssd]/service option.

        :param responder: Responder to enable.
        :type responder: str
        """
        self.config.setdefault('sssd', {})
        svc = self.config['sssd'].get('services', '')
        if responder not in svc:
            self.config['sssd']['services'] += ', ' + responder
            self.config['sssd']['services'].lstrip(', ')

    def import_domain(self, name: str, role: BaseRole) -> None:
        """
        Import SSSD domain from role object.

        :param name: SSSD domain name.
        :type name: str
        :param role: Provider role object to use for import.
        :type role: BaseRole
        :raises ValueError: If unsupported provider is given.
        """
        host = role.host

        if not isinstance(host, ProviderHost):
            raise ValueError(f'Host type {type(host)} can not be imported as domain')

        self.config[f'domain/{name}'] = host.client
        self.config['sssd'].setdefault('domains', '')

        if not self.config['sssd']['domains']:
            self.config['sssd']['domains'] = name
        elif name not in [x.strip() for x in self.config['sssd']['domains'].split(',')]:
            self.config['sssd']['domains'] += ', ' + name

        if self.default_domain is None:
            self.default_domain = name

    def merge_domain(self, name: str, role: BaseRole) -> None:
        """
        Merge SSSD domain configuration from role object into the domain.

        If domain name is not provided then the default domain is used.

        :param name: Target SSSD domain name
        :type name: str
        :param role: Provider role object to use for import.
        :type role: BaseRole
        :raises ValueError: If unsupported provider is given.
        """
        if not isinstance(role.host, ProviderHost):
            raise ValueError(f'Host type {type(role.host)} can not be imported as domain')

        if name is None:
            name = self.default_domain

        if f'domain/{name}' not in self.config:
            raise ValueError(f'Domain "{name}" does not yet exist, create it first')

        self.dom(name).update(role.host.client)

    def config_dumps(self) -> str:
        """
        Get current SSSD configuration.

        :return: SSSD configuration.
        :rtype: str
        """
        return self.__config_dumps(self.config)

    def config_load(self) -> None:
        """
        Load remote SSSD configuration.
        """
        result = self.host.ssh.exec(['cat', '/etc/sssd/sssd.conf'], log_level=SSHLog.Short)
        self.config.clear()
        self.config.read_string(result.stdout)

    def config_apply(self, check_config: bool = True, debug_level: str | None = '0xfff0') -> None:
        """
        Apply current configuration on remote host.

        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        """
        cfg = self.__set_debug_level(debug_level)
        contents = self.__config_dumps(cfg)
        self.fs.write('/etc/sssd/sssd.conf', contents, mode='0600')

        if check_config:
            self.host.ssh.run('sssctl config-check')

    def section(self, name: str) -> dict[str, str]:
        """
        Get sssd.conf section.

        :param name: Section name.
        :type name: str
        :return: Section configuration object.
        :rtype: dict[str, str]
        """
        return self.__get(name)

    def dom(self, name: str) -> dict[str, str]:
        """
        Get sssd.conf domain section.

        :param name: Domain name.
        :type name: str
        :return: Section configuration object.
        :rtype: dict[str, str]
        """
        return self.section(f'domain/{name}')

    def subdom(self, domain: str, subdomain: str) -> dict[str, str]:
        """
        Get sssd.conf subdomain section.

        :param domain: Domain name.
        :type domain: str
        :param subdomain: Subdomain name.
        :type subdomain: str
        :return: Section configuration object.
        :rtype: dict[str, str]
        """
        return self.section(f'domain/{domain}/{subdomain}')

    @property
    def domain(self) -> dict[str, str]:
        """
        Default domain section configuration object.

        Default domain is the first domain imported by :func:`import_domain`.

        :raises ValueError: If no default domain is set.
        :return: Section configuration object.
        :rtype: dict[str, str]
        """
        if self.default_domain is None:
            raise ValueError(f'{self.__class__}.default_domain is not set')

        return self.dom(self.default_domain)

    @domain.setter
    def domain(self, value: dict[str, str]) -> None:
        if self.default_domain is None:
            raise ValueError(f'{self.__class__}.default_domain is not set')

        self.config[f'domain/{self.default_domain}'] = value

    @domain.deleter
    def domain(self) -> None:
        if self.default_domain is None:
            raise ValueError(f'{self.__class__}.default_domain is not set')

        del self.config[f'domain/{self.default_domain}']

    def __get(self, section: str) -> dict[str, str]:
        self.config.setdefault(section, {})
        return self.config[section]

    def __set(self, section: str, value: dict[str, str]) -> None:
        self.config[section] = value

    def __del(self, section: str) -> None:
        del self.config[section]

    sssd: dict[str, str] = property(
        fget=partial(__get, section='sssd'),
        fset=partial(__set, section='sssd'),
        fdel=partial(__del, section='sssd')
    )
    """
    Configuration of the sssd section.
    """

    autofs: dict[str, str] = property(
        fget=partial(__get, section='autofs'),
        fset=partial(__set, section='autofs'),
        fdel=partial(__del, section='autofs')
    )
    """
    Configuration of autofs responder.
    """

    ifp: dict[str, str] = property(
        fget=partial(__get, section='ifp'),
        fset=partial(__set, section='ifp'),
        fdel=partial(__del, section='ifp')
    )
    """
    Configuration of ifp responder.
    """

    kcm: dict[str, str] = property(
        fget=partial(__get, section='kcm'),
        fset=partial(__set, section='kcm'),
        fdel=partial(__del, section='kcm')
    )
    """
    Configuration of kcm responder.
    """

    nss: dict[str, str] = property(
        fget=partial(__get, section='nss'),
        fset=partial(__set, section='nss'),
        fdel=partial(__del, section='nss')
    )
    """
    Configuration of nss responder.
    """

    pac: dict[str, str] = property(
        fget=partial(__get, section='pac'),
        fset=partial(__set, section='pac'),
        fdel=partial(__del, section='pac')
    )
    """
    Configuration of pac responder.
    """

    pam: dict[str, str] = property(
        fget=partial(__get, section='pam'),
        fset=partial(__set, section='pam'),
        fdel=partial(__del, section='pam')
    )
    """
    Configuration of pam responder.
    """

    ssh: dict[str, str] = property(
        fget=partial(__get, section='ssh'),
        fset=partial(__set, section='ssh'),
        fdel=partial(__del, section='ssh')
    )
    """
    Configuration of ssh responder.
    """

    sudo: dict[str, str] = property(
        fget=partial(__get, section='sudo'),
        fset=partial(__set, section='sudo'),
        fdel=partial(__del, section='sudo')
    )
    """
    Configuration of sudo responder.
    """

    @staticmethod
    def __config_dumps(cfg: configparser) -> str:
        """ Convert configparser to string. """
        with StringIO() as ss:
            cfg.write(ss)
            ss.seek(0)
            return ss.read()

    def __set_debug_level(self, debug_level: str | None = None) -> configparser:
        cfg = configparser.ConfigParser()
        cfg.read_dict(self.config)

        if debug_level is None:
            return self.cfg

        sections = ['sssd', 'autofs', 'ifp', 'kcm', 'nss', 'pac', 'pam', 'ssh', 'sudo']
        sections += [section for section in cfg.keys() if section.startswith('domain/')]

        for section in sections:
            cfg.setdefault(section, {})
            if 'debug_level' not in cfg[section]:
                cfg[section]['debug_level'] = debug_level

        return cfg


class SSSDCommonConfiguration(object):
    """
    Common SSSD configuration.

    This class provides shortcuts to setup SSSD for common scenarios.
    """
    def __init__(self, sssd: HostSSSD) -> None:
        self.sssd: HostSSSD = sssd

    def krb5_auth(self, kdc: KDC, domain: str | None = None) -> None:
        """
        Configure auth_provider to krb5, using the KDC from the multihost
        configuration.

        #. Merge KDC configuration into the given domain (or default domain)
        #. Generate /etc/krb5.conf from given KDC role

        :param kdc: KDC role object.
        :type kdc: KDC
        :param domain: Existing domain name, defaults to None (= default domain)
        :type domain: str | None, optional
        :raises ValueError: if invalid domain is given.
        """
        if domain is None:
            domain = self.sssd.default_domain

        if domain is None:
            raise ValueError('No domain specified!')

        self.sssd.merge_domain(domain, kdc)
        self.sssd.fs.write('/etc/krb5.conf', kdc.config(), user='root', group='root', mode='0644')

    def kcm(self, kdc: KDC) -> None:
        """
        Configure Kerberos to allow KCM tests.

        #. Generate /etc/krb5.conf from given KDC role

        :param kdc: KDC role object.
        :type kdc: KDC
        """
        self.sssd.fs.write('/etc/krb5.conf', kdc.config(), user='root', group='root', mode='0644')
