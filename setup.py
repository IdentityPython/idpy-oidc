#!/usr/bin/env python
#
# Copyright (C) 2017 Roland Hedberg, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

__author__ = 'Roland Hedberg'


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        errno = pytest.main(self.test_args)
        sys.exit(errno)


extra_install_requires = []

with open('src/idpyoidc/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

setup(
    name="idpyoidc",
    version=version,
    description="Python implementation of everything OAuth2 and OpenID Connect",
    long_description=README,
    long_description_content_type='text/markdown',
    author="Roland Hedberg",
    author_email="roland@catalogix.se",
    license="Apache 2.0",
    url='https://github.com/IdentityPython/idpy-oidc/',
    packages=["idpyoidc", "idpyoidc/message","idpyoidc/message/oauth2", "idpyoidc/message/oidc",
              "idpyoidc/storage", "idpyoidc/client", "idpyoidc/server", "idpyoidc/server/session",
              "idpyoidc/server/token", "idpyoidc/server/authz",
              "idpyoidc/server/user_authn",
              "idpyoidc/server/user_info",
              "idpyoidc/server/oauth2", "idpyoidc/server/oauth2/add_on",
              "idpyoidc/server/oidc", "idpyoidc/server/oidc/add_on",
              "idpyoidc/client/oidc", "idpyoidc/client/oidc/add_on",
              "idpyoidc/client/provider", "idpyoidc/actor",
              "idpyoidc/client/oauth2", "idpyoidc/client/oauth2/add_on",
              "idpyoidc/client/oauth2/client_credentials"
              ],
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=[
        "cryptojwt==1.7.1",
        "pyOpenSSL",
        "filelock>=3.0.12",
        'pyyaml>=5.1.2',
        "jinja2>=2.11.3",
        "responses>=0.13.0"
    ],
    zip_safe=False,
    cmdclass={'test': PyTest},
)
