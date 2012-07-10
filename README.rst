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

.. _SmartFile: http://www.smartfile.com/
.. _Read more: http://www.smartfile.com/open-source.html