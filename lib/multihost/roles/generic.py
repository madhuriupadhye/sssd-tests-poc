from __future__ import annotations

from abc import ABC, abstractmethod

from .base import BaseObject, BaseRole


class GenericProvider(ABC, BaseRole):
    """
    Generic provider interface. All providers implements this interface.

    .. note::

        This class provides generic interface for provider roles. It can be used
        for type hinting only on parametrized tests that runs on multiple
        topologies.
    """

    @abstractmethod
    def user(self, name: str) -> GenericUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def group(self, name: str) -> GenericGroup:
        """
        Get group object.

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def sudorule(self, name: str) -> GenericSudoRule:
        """
        Get sudo rule object.

        :param name: Sudo rule name.
        :type name: str
        :return: New sudo rule object.
        :rtype: GenericSudoRule
        """
        pass


class GenericADProvider(GenericProvider):
    """
    Generic Active Directory provider interface. Active Directory and Samba
    providers implements this interface.

    .. note::

        This class provides generic interface for Active Directory-based
        roles. It can be used for type hinting only on parametrized tests
        that runs on both Samba and Active Directory.
    """
    pass


class GenericUser(ABC, BaseObject):
    """
    Generic user management.
    """

    @abstractmethod
    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str = 'Secret123',
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> GenericUser:
        """
        Create a new user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: User password, defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> GenericUser:
        """
        Modify existing user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to None
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the user.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get user attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass


class GenericGroup(ABC, BaseObject):
    """
    Generic group management.
    """

    @abstractmethod
    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> GenericGroup:
        """
        Create a new group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> GenericGroup:
        """
        Modify existing group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the group.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get group attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass

    @abstractmethod
    def add_member(self, member: GenericUser | GenericGroup) -> GenericGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: GenericUser | GenericGroup
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def add_members(self, members: list[GenericUser | GenericGroup]) -> GenericGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[GenericUser | GenericGroup]
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def remove_member(self, member: GenericUser | GenericGroup) -> GenericGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: GenericUser | GenericGroup
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def remove_members(self, members: list[GenericUser | GenericGroup]) -> GenericGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[GenericUser | GenericGroup]
        :return: Self.
        :rtype: GenericGroup
        """
        pass


class GenericSudoRule(ABC, BaseObject):
    """
    Generic sudo rule management.
    """

    @abstractmethod
    def add(
        self,
        *,
        user: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        runasgroup: str | GenericGroup | list[str | GenericGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None
    ) -> GenericSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | GenericGroup | list[str  |  GenericGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: GenericSudoRule
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        user: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        runasgroup: str | GenericGroup | list[str | GenericGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None
    ) -> GenericSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | GenericGroup | list[str  |  GenericGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: GenericSudoRule
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the sudo rule.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get sudo rule attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass
