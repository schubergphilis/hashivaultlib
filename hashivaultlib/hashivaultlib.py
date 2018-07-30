#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: hashivaultlib.py
#
# Copyright 2018 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for hashivaultlib

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging
import os
from datetime import timedelta
import concurrent.futures

from dateutil.parser import parse
from hvac import Client

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''2018-05-25'''
__copyright__ = '''Copyright 2018, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


# This is the main prefix used for logging
LOGGER_BASENAME = '''hashivaultlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Vault(Client):
    """Extends the hvac client for vault with some extra handy usability"""

    def __init__(self, *args, **kwargs):
        super(Vault, self).__init__(*args, **kwargs)
        logger_name = u'{base}.{suffix}'.format(base=LOGGER_BASENAME,
                                                suffix=self.__class__.__name__)
        self._logger = logging.getLogger(logger_name)

    def delete_path(self, path):
        """Deletes recursively a path from vault

        Args:
            path: The path to remove

        """
        try:
            subdirs = self.list(path).get('data', {}).get('keys')
            for subdir in subdirs:
                self.delete_path(os.path.join(path, subdir))
            self._logger.info('Deleting directory %s', path)
            self.delete(path)
        except AttributeError:
            self._logger.info('Deleting secret %s', path)
            self.delete(path)

    def retrieve_secrets_from_path(self, path):
        """Retrieves recursively all the secrets from a path in vault

        Args:
            path: The path to retrieve all the secrets for

        """
        class Namespace(object):  # pylint: disable=too-few-public-methods
            """Namespacing utility class"""

            def __init__(self):
                self.secrets = []

        namespace = Namespace()

        def recurse(vault, path):
            """Recurses through a path"""
            try:
                subdirs = vault.list(path).get('data', {}).get('keys')
                for subdir in subdirs:
                    recurse(vault, os.path.join(path, subdir))
                LOGGER.info('Reached directory %s', path)
            except AttributeError:
                LOGGER.info('Extracting secret %s', path)
                secret = vault.read(path)
                secret['original_path'] = path
                namespace.secrets.append(secret)

        recurse(self, path)
        return namespace.secrets

    def restore_secrets(self, secrets):
        """Restores secrets to vault in their original path.

        Args:
            secrets: List of secret dictionaries with "original_path" attribute set

        Returns:
            True on success, False otherwise

        """
        if not isinstance(secrets, (list, tuple)):
            self._logger.error('Please provide a list or tuple of secrets to restore.')
            return False
        for secret in secrets:
            path = secret.get('original_path')
            if not path:
                self._logger.error('No "original_path" found, cannot restore.')
                continue
            data = secret.get('data')
            self._logger.info('Adding secrets to path {}'.format(path))
            self.write(path, **data)
        return True

    @property
    def _token_accessors(self):
        headers = {'X-Vault-Token': self.token}
        url = '{host}/v1/auth/token/accessors?vaultaddr={host}&list=true'.format(host=self._url)
        response = self.session.get(url, headers=headers)
        if not response.ok:
            self._logger.error('Error retrieving accessors.')
        return response.json().get('data', {}).get('keys', []) if response.ok else None

    @property
    def tokens(self):
        """Models the tokens of a vault installation

        Returns:
            list:All tokens of a vault in a Token object format

        """
        headers = {'X-Vault-Token': self.token}
        url = '{host}/v1/auth/token/lookup-accessor?vaultaddr={host}'.format(host=self._url)
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(self.session.post,
                                       url,
                                       headers=headers,
                                       data=json.dumps({"accessor": accessor}))
                       for accessor in self._token_accessors]
            for future in concurrent.futures.as_completed(futures):
                try:
                    response = future.result()
                    response_data = response.json()
                    response.close()
                    yield TokenFactory(self, response_data)
                except Exception:  # pylint: disable=broad-except
                    self._logger.exception('Future failed...')


class TokenFactory(object):  # pylint: disable=too-few-public-methods
    """Factory to create the appropriate Token type"""

    def __new__(cls, vault_instance, data):
        try:
            if 'errors' in data.keys():
                token = BrokenToken(vault_instance, data)
            else:
                token = Token(vault_instance, data)
        except (AttributeError, TypeError):
            LOGGER.error('Response for token seems broken, got :{}'.format(data))
        return token


class Token(object):  # pylint: disable=too-many-public-methods
    """Models a vault token and provides delete capabilities"""

    def __init__(self, vault_instance, data):
        self._vault = vault_instance
        self._data = data

    @property
    def raw_data(self):
        """The raw data of the token

        Returns:
            dict: The raw data of the token

        """
        return self._data

    @property
    def auth(self):
        """Auth data for the token

        Returns:
            The auth data

        """
        return self._data.get('auth')

    @staticmethod
    def _seconds_to_day_format(seconds_):
        str(timedelta(seconds=int(seconds_)))

    @property
    def lease_duration(self):
        """The duration of the lease of the token

        Returns:
            string: The duration of the lease of the token

        """
        return self._data.get('lease_duration')

    @property
    def lease_id(self):
        """The lease ID

        Returns:
            string: The lease ID

        """
        return self._data.get('lease_id')

    @property
    def renewable(self):
        """A flag on whether the token is renewable

        Returns:
            bool: True if token is renewable, False otherwise

        """
        return self._data.get('renewable')

    @property
    def request_id(self):
        """The id of the request for the token

        Returns:
            string: The id of the request for the token

        """
        return self._data.get('request_id')

    @property
    def warnings(self):
        """The warnings of the token

        Returns:
            The warnings of the token

        """
        return self._data.get('warnings')

    @property
    def wrap_info(self):
        """The wrap info of the token

        Returns:
            The wrap info of the token

        """
        return self._data.get('wrap_info')

    @property
    def accessor(self):
        """The accessor token of the token

        Returns:
            string: The accessor token of the token

        """
        return self._data.get('data', {}).get('accessor')

    @property
    def creation_time(self):
        """The creation time of the token in seconds

        Returns:
            string: The creation time of the token in seconds

        """
        return self._data.get('data', {}).get('creation_time')

    @property
    def creation_time_day_format(self):
        """The creation time of the token in a day duration format

        Returns:
            string: The creation time of the token in a day duration format

        """
        return self._seconds_to_day_format(self.creation_time)

    @property
    def creation_ttl(self):
        """The creation ttl of the token in seconds

        Returns:
            string: The creation ttl of the token in seconds

        """
        return self._data.get('data', {}).get('creation_ttl')

    @property
    def creation_ttl_day_format(self):
        """The creation ttl of the token in a day duration format

        Returns:
            string: The creation ttl of the token in a day duration format

        """
        return self._seconds_to_day_format(self.creation_ttl)

    @property
    def display_name(self):
        """The display name of the token

        Returns:
            string: The display name of the token

        """
        return self._data.get('data', {}).get('display_name', '')

    @property
    def expire_time(self):
        """The expire time of the token

        Returns:
            datetime: The expire time of the token if any, None otherwise

        """
        try:
            date_ = parse(self._data.get('data', {}).get('expire_time'))
        except (ValueError, TypeError):
            date_ = None
        return date_

    @property
    def issue_time(self):
        """The issue time of the token

        Returns:
            datetime: The issue time of the token

        """
        try:
            date_ = parse(self._data.get('data', {}).get('issue_time'))
        except (ValueError, TypeError):
            date_ = None
        return date_

    @property
    def explicit_max_ttl(self):
        """The explicit max ttl

        Returns:
            string: The explicit max ttl

        """
        return self._data.get('data', {}).get('explicit_max_ttl')

    @property
    def explicit_max_ttl_day_format(self):
        """The explicit max ttl in a day duration format

        Returns:
            string: The explicit max ttl in a day duration format

        """
        return self._seconds_to_day_format(self.explicit_max_ttl)

    @property
    def id(self):  # pylint: disable=invalid-name
        """The id of the token

        Returns:
            string: The id of the token

        """
        return self._data.get('data', {}).get('id')

    @property
    def meta(self):
        """The meta of the token

        Returns:
            string: The meta of the token

        """
        return self._data.get('data', {}).get('meta')

    @property
    def num_uses(self):
        """The number of uses of the token

        Returns:
            string: The number of uses of the token

        """
        return self._data.get('data', {}).get('num_uses')

    @property
    def orphan(self):
        """Flag on whether the token is orphan

        Returns:
            bool: True if the token is orphan, False otherwise

        """
        return self._data.get('data', {}).get('orphan')

    @property
    def path(self):
        """The path to create the token

        Returns:
            string: The path to create the token

        """
        return self._data.get('data', {}).get('path')

    @property
    def policies(self):
        """The policies this token has enforced upon

        Returns:
            list: The policies of the token

        """
        return self._data.get('data', {}).get('policies', [])

    @property
    def ttl(self):
        """The ttl is seconds

        Returns:
            string: The ttl is seconds

        """
        return self._data.get('data', {}).get('ttl')

    @property
    def ttl_day_format(self):
        """The ttl in a day duration format

        Returns:
            string: The ttl in a day duration format

        """
        return self._seconds_to_day_format(self.ttl)

    def delete(self):
        """Deletes the token by removing the accessor from the vault instance"""
        self._vault.revoke_token(self.accessor, accessor=True)


class BrokenToken(Token):
    """Models a broken token with only an accessor ID and errors messages"""

    @property
    def errors(self):
        """The errors of the token"""
        return self._data.get('errors')
