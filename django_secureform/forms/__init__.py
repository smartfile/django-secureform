import time
import string
from Crypto.Random import random
from Crypto.Cipher import Blowfish
from django import forms
from django.conf import settings
from django.core.cache import cache
from django.forms import widgets
from django.forms.util import ErrorDict
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

# Duplicated from django.forms, can't be imported!
NON_FIELD_ERRORS = '__all__'

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


# Duplicated from django.forms, can't be imported!
def pretty_name(name):
    if not name:
        return u''
    return name.replace('_', ' ').capitalize()


class StaleFormException(Exception):
    "Raised if a form's timestamp is too old."


class ReplayedFormException(Exception):
    "Raised if a form's nonce value has been seen before."


class HoneypotFormException(Exception):
    "Raised if a honeypot field receives a value."


class InvalidFormException(Exception):
    "Raised if a fields do not map properly."


class HoneypotField(forms.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.update({
            'required': False,
            'max_length': 16,
        })
        super(HoneypotField, self).__init__(*args, **kwargs)


class SecureForm(forms.Form):
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
        super(SecureForm, self).__init__(*args, **kwargs)
        # Use defaults, unless the caller overrode them.
        self.secure_field_name = kwargs.pop('secure_field_name', DEFAULT_FIELD_NAME)
        self.form_ttl = kwargs.pop('form_ttl', DEFAULT_FORM_TTL)
        self.honeypots = kwargs.pop('honeypots', DEFAULT_HONEYPOTS)
        self.include_jquery = kwargs.pop('include_jquery', DEFAULT_INCLUDE_JQUERY)
        crypt_key = kwargs.pop('crypt_key', DEFAULT_CRYPT_KEY)
        self.crypt = Blowfish.new(crypt_key)
        self.fields[self.secure_field_name] = forms.CharField(required=True, widget=widgets.HiddenInput)
        self.__secured = False

    def __iter__(self):
        if not self.__secured:
            # Only secure on the first iteration.
            self.__secured = True
            self.secure_data()
        for name in self.fields:
            yield self[name]

    def _script(self):
        honeypots = [n for (n, f) in self.fields.items() if isinstance(f, HoneypotField)]
        func = random_name(choices=string.letters)
        name = random_name(choices=string.letters, length=2)
        obs = []
        for honeypot in honeypots:
            orig = [c for c in honeypot]
            shuf = random.sample(orig, len(orig))
            random.shuffle(shuf)
            pos = map(shuf.index, orig)
            obs.extend([
                'var %s = [\'%s\'];' % (name, '\', \''.join(shuf)),
                '%s(%s);' % (func, ' + '.join(['%s[%s]' % (name, p) for p in pos]))
            ])
        scripts = [
            SCRIPT_TAG % dict(function=func, obfuscated='\n'.join(obs))
        ]
        if self.include_jquery:
            scripts.insert(0, JQUERY_TAG)
        return mark_safe('\n'.join(scripts))
    script = property(_script)

    def decode_data(self):
        if not self.is_bound:
            return
        import pdb; pdb.set_trace()
        data = {}
        secure = self.data[self.secure_field_name]
        secure = self.crypt.decrypt(secure.decode('hex')).rstrip()
        secure = simplejson.loads(secure)
        timestamp = secure['t']
        if timestamp < time.time() - self.form_ttl:
            # Form data is too old, reject the form.
            raise StaleFormException(_('The form data is more than %s seconds old.') %
                                      self.form_ttl)
        nonce = secure['n']
        if cache.get(nonce) != None:
            # Our nonce is in our cache, it has been seend, possible replay!
            raise ReplayedFormException(_('This form has already been submitted.'))
        # We only need to keep the nonce around for as long as the ttl (timeout). After
        # that, the timestamp check will refuse the form.
        cache.set(nonce, nonce, self.form_ttl)
        for sname, name in secure['f'].items():
            if name == self.secure_field_name:
                data[name] = self.data[name]
                continue
            if name is None:
                # This field is a honeypot.
                if self.data.get(name):
                    # Having a value in the honeypot field is bad news!
                    raise HoneypotFormException(_('Unexpected value in form field.'))
                continue
            try:
                data[name] = self.data[sname]
            except KeyError:
                raise InvalidFormException(_('Form data contains invalid fields.'))
        return data

    def full_clean(self):
        "Uses decode_data() to convert fields back to their rightful names."
        self._errors = ErrorDict()
        try:
            self.data = self.decode_data()
        except (StaleFormException, ReplayedFormException), e:
            self._errors[NON_FIELD_ERRORS] = self.error_class([str(e)])
        except Exception, e:
            self._errors[NON_FIELD_ERRORS] = self.error_class([_('Form verification failed. Please try again.')])
        if not self._errors:
            super(SecureForm, self).full_clean()

    def secure_data(self):
        "Prepares the secure data before the form is rendered."
        field_map = {}
        # Rename the real fields, create a map of new random names to the rightful
        # name
        for name in self.fields.keys():
            if name == self.secure_field_name:
                continue
            sname = random_name()
            field = self.fields.pop(name)
            field_map[sname] = name
            self.fields[sname] = field
            # Preserve the field name unless there is an explicit label:
            if not field.label:
                # Pretty-up the name, just like BoundField.
                field.label = pretty_name(name)
        # Add in some honeypots (if asked to).
        for i in range(1, self.honeypots):
            sname = random_name()
            field_map[sname] = None
            # Don't always put the honeypot fields at the end of the form.
            i = random.randint(0, len(self.fields) - 1)
            self.fields.insert(i, sname, HoneypotField())
        secure = {
            't': time.time(),
            'n': random_name(),
            'f': field_map,
        }
        secure = simplejson.dumps(secure)
        # Pad to length divisible by 8.
        secure += ' ' * (8 - (len(secure) % 8))
        secure = self.crypt.encrypt(secure)
        self.fields[self.secure_field_name].initial = secure.encode('hex')
