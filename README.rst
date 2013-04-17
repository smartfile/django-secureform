.. figure:: https://travis-ci.org/smartfile/django-secureform.png
   :alt: Travis CI Status
   :target: https://travis-ci.org/smartfile/django-secureform

A `SmartFile`_ Open Source project. `Read more`_ about how SmartFile
uses and contributes to Open Source software.

.. figure:: http://www.smartfile.com/images/logo.jpg
   :alt: SmartFile

Introduction
------------

Provides protection against spammers and scammers.

Installation
------------

Install using pip `pip install django-secureform`

Then install the application into your Django project in settings.py. There are also optional settings
which will affect the behavior of SecureForm instances.

::

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

Usage
-----

::

    from django_secureform.forms import SecureForm


    # Define your form class as usual.
    class MySecureForm(SecureForm):
        class Meta:
            # Override options in settings.py for this class.
            include_jquery = False

        name = forms.CharField()


Unit Testing
------------

If you want to write unit tests for forms that derive from SecureForm, you will
need to let this application know you are testing. SecureForm looks for
settings.TESTING to evaluate to True. If so, it disables the security allowing
the Django test client to send POST data using the original field names.

In the future, I would rather provide tools so that testing can happen with
security enabled, but this is a quick workaround. Our test framework uses an
environment variable to set settings.TESTING. For example, in settings.py...

::

    import os

    TESTING = True if 'TESTING' in os.environ else False

.. _SmartFile: http://www.smartfile.com/
.. _Read more: http://www.smartfile.com/open-source.html
