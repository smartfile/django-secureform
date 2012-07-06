import os
import unittest
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
from django import forms
from django.db import models
from django.forms.forms import NON_FIELD_ERRORS
from django_secureform.forms import SecureForm


def get_form_sname(form, name):
    for sname, v in form._secure_field_map.items():
        if v and v == name:
            return sname
    raise KeyError(name)


def get_form_honeypot(form):
    for sname, v in form._secure_field_map.items():
        if v is None:
            return sname
    raise Exception('No honeypots found.')


def get_form_secure_data(form):
    # We must copy over the security data.
    return form._meta.secure_field_name, form[form._meta.secure_field_name].value()


class BasicForm(SecureForm):
    name = forms.CharField(required=True, max_length=16)


class FormTestCase(unittest.TestCase):
    klass = BasicForm

    def setUp(self):
        self.form = self.klass()
        self.form.secure_data()

    def get_form(self, **kwargs):
        data = dict((get_form_secure_data(self.form), ))
        for n, v in kwargs.items():
            data[get_form_sname(self.form, n)] = v
        return self.klass(data=data)


class BasicTestCase(FormTestCase):
    def test_valid(self):
        post = self.get_form(name='foobar')
        self.assertTrue(post.is_valid())

    def test_missing(self):
        post = self.get_form()
        self.assertFalse(post.is_valid())
        self.assertIn('name', post._errors)

    def test_replay(self):
        post = self.get_form(name='foobar')
        post.is_valid()
        post = self.get_form(name='foobar')
        self.assertFalse(post.is_valid())
        self.assertIn(NON_FIELD_ERRORS, post._errors)
        self.assertIn('This form has already been submitted.', post._errors[NON_FIELD_ERRORS])

    def test_honeypot(self):
        honeypot = get_form_honeypot(self.form)
        data = dict((get_form_secure_data(self.form), ))
        data[honeypot] = 'mmm, hunny!'
        data[get_form_sname(self.form, 'name')] = 'foobar'
        post = self.klass(data=data)
        self.assertFalse(post.is_valid())
        self.assertIn(NON_FIELD_ERRORS, post._errors)
        self.assertIn('Unexpected value in form field.', post._errors[NON_FIELD_ERRORS])


if __name__ == '__main__':
    unittest.main()
