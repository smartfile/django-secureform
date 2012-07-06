import time
import string
from Crypto.Random import random
from Crypto.Cipher import Blowfish
from django import forms
from django.conf import settings
from django.core.cache import cache
from django.forms import widgets
from django.forms.util import ErrorDict
from django.forms.forms import pretty_name, NON_FIELD_ERRORS, BoundField, DeclarativeFieldsMetaclass
from django.utils import simplejson
from django.utils.translation import ugettext as _
from django.utils.safestring import mark_safe

# Chars that are safe to use in field names.
SAFE_CHARS = string.ascii_letters + string.digits

JQUERY_TAG = '<script type="text/javascript" src="http://code.jquery.com/jquery-1.7.2.min.js"></script>'
SCRIPT_TAG = '''<script type="text/javascript">
function %(function)s(n) {
    $('p, li, tr').has('input[id="id_' + n + '"]').remove();
}
%(obfuscated)s
</script>'''

# Allow the user to specify an encryption key separate from the Django
# SECRET_KEY if they wish.
DEFAULT_CRYPT_KEY = getattr(settings, 'SECUREFORM_CRYPT_KEY', getattr(settings, 'SECRET_KEY', None))
# The user can override the secure field name.
DEFAULT_FIELD_NAME = getattr(settings, 'SECUREFORM_FIELD_NAME', 'secure')
# Give the user twenty minutes to fill out the form..
DEFAULT_FORM_TTL = getattr(settings, 'SECUREFORM_TTL', 1200)
DEFAULT_HONEYPOTS = getattr(settings, 'SECUREFORM_HONEYPOTS', 2)
DEFAULT_INCLUDE_JQUERY = getattr(settings, 'SECUREFORM_INCLUDE_JQUERY', True)

def random_name(choices=SAFE_CHARS, length=16):
    return ''.join(random.sample(choices, length))


class SecureFormException(Exception):
    "Base exception for security faults."


class StaleFormException(SecureFormException):
    "Raised if a form's timestamp is too old."


class ReplayedFormException(SecureFormException):
    "Raised if a form's nonce value has been seen before."


class HoneypotFormException(SecureFormException):
    "Raised if a honeypot field receives a value."


class InvalidFormException(SecureFormException):
    "Raised if a fields do not map properly."


class HoneypotField(forms.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.update({
            'required': False,
            'max_length': 16,
        })
        super(HoneypotField, self).__init__(*args, **kwargs)


class InitialValueField(forms.CharField):
    "A field that always assumes the initial value."
    def bound_data(self, data, initial):
        return initial


class SecureBoundField(BoundField):
    def _errors(self):
        """
        Translates errors from field's secure name to the regular name (which is
        how errors are stored in the form.)
        """
        name = self.form._secure_field_map.get(self.name)
        return self.form.errors.get(name, self.form.error_class())
    errors = property(_errors)


class SecureFormOptions(object):
    def __init__(self, options=None):
        self.secure_field_name = getattr(options, 'secure_field_name', DEFAULT_FIELD_NAME)
        self.form_ttl = getattr(options, 'form_ttl', DEFAULT_FORM_TTL)
        self.honeypots = getattr(options, 'honeypots', DEFAULT_HONEYPOTS)
        self.include_jquery = getattr(options, 'include_jquery', DEFAULT_INCLUDE_JQUERY)


class SecureFormMetaclass(DeclarativeFieldsMetaclass):
    def __new__(cls, name, bases, attrs):
        new_class = super(SecureFormMetaclass, cls).__new__(cls, name, bases, attrs)
        new_class._meta = SecureFormOptions(getattr(new_class, 'Meta', None))
        return new_class


class SecureFormBase(forms.Form):
    """This form is meant to defeat spam bots. It does this using a couple of techniques.

      1. First of all, it will randomize the form field names.
      2. It will add a hidden field which contains an encrypted map of random field names
         to actual field names. It will also contain a timestamp and nonce value to defeat
         replay attacks.
      3. It will create two canary or honeypot fields that are expected to be left blank.
      4. It will include a snippet of javascript that hides the two honeypot fields using CSS.

    This should be effective to block spammers of multiple varieties.

      1. Spambots that simply replay the form submission will be foiled by replay protection.
      2. Spambots that fetch then post the form back will be foiled by the honeypot fields
         unless they have a full javascript engine.
      3. Humans on the other hand will still be able to submit the form, whether they are
         legitimate or not. However, this activity will be cost prohibitive for spammers.
    """

    def __init__(self, *args, **kwargs):
        super(SecureFormBase, self).__init__(*args, **kwargs)
        # Use defaults, unless the caller overrode them.
        crypt_key = kwargs.pop('crypt_key', DEFAULT_CRYPT_KEY)
        self.crypt = Blowfish.new(crypt_key)
        self.fields[self._meta.secure_field_name] = InitialValueField(required=False, widget=widgets.HiddenInput)
        self.__secured = False
        self._secure_field_map = {}

    def __iter__(self):
        if not self.__secured:
            # Only secure on the first iteration.
            self.__secured = True
            self.secure_data()
        for name in self.fields:
            yield self[name]

    def __getitem__(self, name):
        "Returns a BoundField with the given name."
        try:
            field = self.fields[name]
        except KeyError:
            raise KeyError('Key %r not found in Form' % name)
        return SecureBoundField(self, field, name)

    def _script(self):
        if not self._meta.honeypots:
            return ''
        honeypots = [n for (n, f) in self.fields.items() if isinstance(f, HoneypotField)]
        func = random_name(choices=string.letters)
        name = random_name(choices=string.letters, length=2)
        obs = []
        for honeypot in honeypots:
            orig = [c for c in honeypot]
            shuf = random.sample(orig, len(orig))
            pmap = map(shuf.index, orig)
            obs.extend([
                'var %s = [\'%s\'];' % (name, '\', \''.join(shuf)),
                '%s(%s);' % (func, ' + '.join(['%s[%s]' % (name, p) for p in pmap]))
            ])
        scripts = [
            SCRIPT_TAG % dict(function=func, obfuscated='\n'.join(obs))
        ]
        if self._meta.include_jquery:
            scripts.insert(0, JQUERY_TAG)
        return mark_safe('\n'.join(scripts))
    script = property(_script)

    def decode_data(self):
        if not self.is_bound:
            return
        cleaned_data = {}
        secure = self.data[self._meta.secure_field_name]
        secure = self.crypt.decrypt(secure.decode('hex')).rstrip()
        secure = simplejson.loads(secure)
        timestamp = secure['t']
        if timestamp < time.time() - self._meta.form_ttl:
            # Form data is too old, reject the form.
            raise StaleFormException(_('The form data is more than %s seconds old.') %
                                       self._meta.form_ttl)
        nonce = secure['n']
        if cache.get(nonce) != None:
            # Our nonce is in our cache, it has been seend, possible replay!
            raise ReplayedFormException(_('This form has already been submitted.'))
        # We only need to keep the nonce around for as long as the ttl (timeout). After
        # that, the timestamp check will refuse the form.
        cache.set(nonce, nonce, self._meta.form_ttl)
        self._secure_field_map = secure['f']
        for sname, name in self._secure_field_map.items():
            if name == self._meta.secure_field_name:
                cleaned_data[name] = self.data[name]
                continue
            if name is None:
                # This field is a honeypot.
                if self.data.get(sname):
                    # Having a value in the honeypot field is bad news!
                    raise HoneypotFormException(_('Unexpected value in form field.'))
                continue
            try:
                cleaned_data[name] = self.data[sname]
            except KeyError:
                # The field is missing from the data, that is OK, regular validation
                # will catch this if the field is required.
                pass
        self.data = cleaned_data

    def _clean_secure(self):
        "Uses decode_data() to convert fields back to their rightful names."
        try:
            self.decode_data()
        except SecureFormException, e:
            self._errors[NON_FIELD_ERRORS] = self.error_class([str(e)])
        except Exception, e:
            self._errors[NON_FIELD_ERRORS] = self.error_class([_('Form verification failed. Please try again.')])

    def full_clean(self):
        "Does secureform validation, then regular validation."
        self._errors = ErrorDict()
        self._clean_secure()
        if not self._errors:
            super(SecureFormBase, self).full_clean()

    def secure_data(self):
        "Prepares the secure data before the form is rendered."
        # Empty out the previous map, we will generate a new one.
        self._secure_field_map = {}
        labels = []
        for name in self.fields.keys():
            if name == self._meta.secure_field_name:
                continue
            sname = random_name()
            field = self.fields.pop(name)
            self._secure_field_map[sname] = name
            self.fields[sname] = field
            # Preserve the field name unless there is an explicit label:
            if not field.label:
                # Pretty-up the name, just like BoundField.
                field.label = pretty_name(name)
            labels.append(field.label)
        # Add in some honeypots (if asked to).
        for i in range(1, self._meta.honeypots):
            sname = random_name()
            self._secure_field_map[sname] = None
            # Don't always put the honeypot fields at the end of the form.
            i = random.randint(0, len(self.fields) - 1)
            # Give the honeypot a label cloned from a legit field.
            rlabel = random.choice(labels)
            self.fields.insert(i, sname, HoneypotField(label=rlabel))
        secure = {
            't': time.time(),
            'n': random_name(),
            'f': self._secure_field_map,
        }
        secure = simplejson.dumps(secure)
        # Pad to length divisible by 8.
        secure += ' ' * (8 - (len(secure) % 8))
        secure = self.crypt.encrypt(secure)
        self.fields[self._meta.secure_field_name].initial = secure.encode('hex')


class SecureForm(SecureFormBase):
    __metaclass__ = SecureFormMetaclass
