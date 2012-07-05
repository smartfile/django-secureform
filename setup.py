#!/bin/env python

from distutils.core import setup

name = 'django_secureform'
version = '0.1'
release = '1'
versrel = version + '-' + release
download_url = 'https://github.com/downloads/btimby/django-secureform' \
                           '/' + name + '-' + versrel + '.tar.gz'
description = """\
A `SmartFile`_ Open Source project. `Read more`_ about how SmartFile
uses and contributes to Open Source software.

.. figure:: http://www.smartfile.com/images/logo.jpg
   :alt: SmartFile

Introduction
----

Provides protection against spammers and scammers.

Installation
----

Install using pip `pip install django-secureform`

Then install the application into your Django project in settings.py. There are also optional settings
which will affect the behavior of SecureForm instances.

```python
INSTALLED_APPS += ('django_secureform', )

# If you wish to use an encryption key other than Django's SECRET_KEY
SECUREFORM_CRYPT_KEY = 'super-secret encryption key'

# This is the name of the hidden field added to the form to contain
# security data.
SECUREFORM_FIELD_NAME = 'foobar'

# The number of seconds allowed between form rendering and submittal.
SECUREFORM_TTL = 300

# The number of honeypot fields added to the form.
SECUREFORM_HONEYPOTS = 1

# By default, jQuery is needed to hide honeypots. If you already
# use jQuery in your app, you can disable this feature (preventing
# a duplicate script reference to jQuery).
SECUREFORM_INCLUDE_JQUERY = False
```

Usage
----

```python
from django_secureform.forms import SecureForm


# Define your form class as usual.
def MySecureForm(SecureForm):
    name = forms.CharField()
```
"""


setup(
    name = name,
    version = versrel,
    description = 'Provides protection against spammers and scammers.',
    long_description = description,
    author = 'Ben Timby',
    author_email = 'btimby@gmail.com',
    maintainer = 'Ben Timby',
    maintainer_email = 'btimby@gmail.com',
    url = 'http://github.com/btimby/django-secureform/',
    download_url = download_url,
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
