#! /usr/bin/python3

# Copyright 2012-2015 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages
import os

version = "4.0.54"

versionfile_path = os.path.join("globus","connect","server", "version")
oldversion = None
if os.path.exists(versionfile_path):
    oldversionfile = open(versionfile_path, "r")
    try:
        oldversion = oldversionfile.read().strip()
    finally:
        oldversionfile.close()

if version != oldversion:
    versionfile = open(versionfile_path, "w")
    try:
        versionfile.write(version + "\n")
    finally:
        versionfile.close()

setup(name='globus_connect_server',
    version=version,
    platforms='none',
    description='Globus Connect Server',
    author='Globus Toolkit',
    author_email='support@globus.org',
    url='https://www.globus.org/globus-connect-server',
    packages=find_packages(),
    package_data={
        'globus.connect.security': [
                '*.pem',
                '*.signing_policy',
                'cilogon-crl-fetch',
                'cilogon-idplist.xml'],
        'globus.connect.server': [
                'mapapp-template',
                'version'
        ]
    },
    data_files=[
        ( '/etc', [ 'globus-connect-server.conf' ]),
        (
            '/usr/share/man/man8', [
                'man/man8/globus-connect-server-setup.8',
                'man/man8/globus-connect-server-cleanup.8',
                'man/man8/globus-connect-server-id-setup.8',
                'man/man8/globus-connect-server-id-cleanup.8',
                'man/man8/globus-connect-server-io-setup.8',
                'man/man8/globus-connect-server-io-cleanup.8',
                'man/man8/globus-connect-server-web-setup.8',
                'man/man8/globus-connect-server-web-cleanup.8'
            ]
        )
    ],
    entry_points={
        'console_scripts': [
            '{}={}:main'.format(
                name, name.replace('-', '.'))
                for name in [
                    'globus-connect-server-setup',
                    'globus-connect-server-cleanup',
                    'globus-connect-server-id-setup',
                    'globus-connect-server-id-cleanup',
                    'globus-connect-server-io-setup',
                    'globus-connect-server-io-cleanup',
                    'globus-connect-server-web-setup',
                    'globus-connect-server-web-cleanup',
                ]
        ]
    },
    install_requires=[
        'requests',
        'six',
    ],
    namespace_packages=[
        'globus'
    ],
)
