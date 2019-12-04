#!/bin/env python

import os
from distutils.core import setup

name = 'django-secureform'
version = '0.3'
release = '2'
versrel = version + '-' + release
readme = os.path.join(os.path.dirname(__file__), 'README.rst')
long_description = open(readme).read()

setup(
    name = name,
    version = versrel,
    description = 'Provides protection against spammers and scammers.',
    long_description = long_description,
    author = 'Ben Timby',
    author_email = 'btimby@gmail.com',
    maintainer = 'Ben Timby',
    maintainer_email = 'btimby@gmail.com',
    url = 'http://github.com/smartfile/' + name + '/',
    license = 'GPLv3',
    packages = [
        "django_secureform",
        "django_secureform.forms",
    ],
    classifiers = (
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Software Development :: Libraries :: Python Modules',
    ),
)
