from __future__ import annotations

from typing import Any

import jc

from ..host import MultihostHost
from .base import MultihostUtility


class UnixObject(object):
    """
    Generic Unix object.
    """

    def __init__(self, id: int | None, name: str | None) -> None:
        """
        :param id: Object ID.
        :type id: int | None
        :param name: Object name.
        :type name: str | None
        """
        self.id: int | None = id
        """
        ID.
        """

        self.name: str | None = name
        """
        Name.
        """

    def __str__(self) -> str:
        return f'({self.id},"{self.name}")'

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, str):
            return o == self.name
        elif isinstance(o, int):
            return o == self.id
        elif isinstance(o, tuple):
            if len(o) != 2 or not isinstance(o[0], int) or not isinstance(o[1], str):
                raise NotImplementedError(f'Unable to compare {type(o)} with {self.__class__}')

            (id, name) = o
            return id == self.id and name == self.name
        elif isinstance(o, UnixObject):
            # Fallback to identity comparison
            return NotImplemented

        raise NotImplementedError(f'Unable to compare {type(o)} with {self.__class__}')


class UnixUser(UnixObject):
    """
    Unix user.
    """
    pass


class UnixGroup(UnixObject):
    """
    Unix group.
    """
    pass


class IdEntry(object):
    """
    Result of ``id``
    """

    def __init__(self, user: UnixUser, group: UnixGroup, groups: list[UnixGroup]) -> None:
        self.user: UnixUser = user
        """
        User information.
        """

        self.group: UnixGroup = group
        """
        Primary group.
        """

        self.groups: list[UnixGroup] = groups
        """
        Secondary groups.
        """

    def memberof(self, groups: int | str | tuple(int, str) | list[int | str | tuple(int, str)]) -> bool:
        """
        Check if the user is member of give group(s).

        Group specification can be either a single gid or group name. But it can
        be also a tuple of (gid, name) where both gid and name must match or list
        of groups where the user must be member of all given groups.

        :param groups: _description_
        :type groups: int | str | tuple
        :return: _description_
        :rtype: bool
        """
        if isinstance(groups, (int, str, tuple)):
            return groups in self.groups

        return all(x in self.groups for x in groups)

    def __str__(self) -> str:
        return f'{{user={str(self.user)},group={str(self.group)},groups={str(self.groups)}}}'

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> IdEntry:
        user = UnixUser(d['uid']['id'], d['uid'].get('name', None))
        group = UnixGroup(d['gid']['id'], d['gid'].get('name', None))
        groups = []

        for secondary_group in d['groups']:
            groups.append(UnixGroup(secondary_group['id'], secondary_group.get('name', None)))

        return cls(user, group, groups)

    @classmethod
    def FromOutput(cls, stdout: str) -> IdEntry:
        return cls.FromDict(jc.parse('id', stdout))


class PasswdEntry(object):
    """
    Result of ``getent group``
    """

    def __init__(self, name: str, password: str, uid: int, gid: int, gecos: str, home: str, shell: str) -> None:
        self.name: str | None = name
        """
        User name.
        """

        self.password: str | None = password
        """
        User password.
        """

        self.uid: int = uid
        """
        User id.
        """

        self.gid: int = gid
        """
        Group id.
        """

        self.gecos: str | None = gecos
        """
        GECOS.
        """

        self.home: str | None = home
        """
        Home directory.
        """

        self.shell: str | None = shell
        """
        Login shell.
        """

    def __str__(self) -> str:
        return f'({self.name}:{self.password}:{self.uid}:{self.gid}:{self.gecos}:{self.home}:{self.shell})'

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> PasswdEntry:
        return cls(
            name=d.get('username', None),
            password=d.get('password', None),
            uid=d.get('uid', None),
            gid=d.get('gid', None),
            gecos=d.get('gecos', None),
            home=d.get('home', None),
            shell=d.get('shell', None),
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> PasswdEntry:
        result = jc.parse('passwd', stdout)

        if len(result) != 1:
            raise ValueError('More then one entry was returned')

        return cls.FromDict(result[0])


class GroupEntry(object):
    """
    Result of ``getent group``
    """

    def __init__(self, name: str, password: str, gid: int, members: list[str]) -> None:
        self.name: str | None = name
        """
        Group name.
        """

        self.password: str | None = password
        """
        Group password.
        """

        self.gid: int = gid
        """
        Group id.
        """

        self.members: list[str] = members
        """
        Group members.
        """

    def __str__(self) -> str:
        return f'({self.name}:{self.password}:{self.gid}:{",".join(self.members)})'

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> GroupEntry:
        return cls(
            name=d.get('group_name', None),
            password=d.get('password', None),
            gid=d.get('gid', None),
            members=d.get('members', []),
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> GroupEntry:
        result = jc.parse('group', stdout)

        if len(result) != 1:
            raise ValueError('More then one entry was returned')

        return cls.FromDict(result[0])


class HostTools(MultihostUtility):
    """
    Run various standard commands on remote host.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.getent: HostGetent = HostGetent(host)
        """
        Interface to getent command.
        """

    def id(self, name: str) -> IdEntry | None:
        """
        Run ``id $name`` command.

        :param name: User name or id.
        :type name: str | int
        :return: id data, None if not found
        :rtype: IdEntry | None
        """
        command = self.host.ssh.exec(['id', name], raise_on_error=False)
        if command.rc != 0:
            return None

        return IdEntry.FromOutput(command.stdout)

    def expect(self, script: str) -> int:
        """
        Execute expect script and return its return code.

        :param script: Expect script.
        :type script: str
        :return: Return code.
        :rtype: int
        """
        result = self.host.ssh.run('/bin/expect', input=script, raise_on_error=False)
        return result.rc


class HostGetent(MultihostUtility):
    """
    Interface to getent command.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

    def passwd(self, name: str | int) -> PasswdEntry | None:
        """
        Call ``getent passwd $name``

        :param name: User name or id.
        :type name: str | int
        :return: passwd data, None if not found
        :rtype: PasswdEntry | None
        """
        return self.__exec(PasswdEntry, 'passwd', name)

    def group(self, name: str | int) -> GroupEntry | None:
        """
        Call ``getent group $name``

        :param name: Group name or id.
        :type name: str | int
        :return: group data, None if not found
        :rtype: PasswdEntry | None
        """
        return self.__exec(GroupEntry, 'group', name)

    def __exec(self, cls, cmd: str, name: str | int) -> Any:
        command = self.host.ssh.exec(['getent', cmd, name], raise_on_error=False)
        if command.rc != 0:
            return None

        return cls.FromOutput(command.stdout)
