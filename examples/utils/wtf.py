# -*- coding: utf-8 -*-
"""
    soxo.wtf
    ~~~~~~~~~~~~
    
    wtforms extension
    :license: BSD
"""

import warnings
import uuid

from wtforms import IntegerField as _IntegerField
from wtforms import DecimalField as _DecimalField
from wtforms import DateField as _DateField
from wtforms.widgets import Input

from wtforms.fields import BooleanField, DecimalField, DateField, \
    DateTimeField, FieldList, FloatField, FormField, \
    HiddenField, IntegerField, PasswordField, RadioField, SelectField, \
    SelectMultipleField, SubmitField, TextField, TextAreaField

from wtforms.validators import Email, email, EqualTo, equal_to, \
    IPAddress, ip_address, Length, length, NumberRange, number_range, \
    Optional, optional, Required, required, Regexp, regexp, \
    URL, url, AnyOf, any_of, NoneOf, none_of

from wtforms.widgets import CheckboxInput, FileInput, HiddenInput, \
    ListWidget, PasswordInput, RadioInput, Select, SubmitInput, \
    TableWidget, TextArea, TextInput

from wtforms.fields import FileField as _FileField


try:
    import sqlalchemy
    _is_sqlalchemy = True
except ImportError:
    _is_sqlalchemy = False


from wtforms import Form as BaseForm
from wtforms import fields, widgets, validators, ValidationError


__all__  = ['Form', 'ValidationError',
            'fields', 'validators', 'widgets', 'html5']

__all__ += fields.__all__
__all__ += validators.__all__
__all__ += widgets.__all__

if _is_sqlalchemy:
    from wtforms.ext.sqlalchemy.fields import QuerySelectField, \
        QuerySelectMultipleField

    __all__ += ['QuerySelectField', 
                'QuerySelectMultipleField']

    for field in (QuerySelectField, 
                  QuerySelectMultipleField):

        setattr(fields, field.__name__, field)


def _generate_csrf_token():
    return str(uuid.uuid4())


class Form(BaseForm):

    """
    In addition this **Form** implementation has automatic CSRF handling.
    """

    csrf = fields.HiddenField()

    def __init__(self, request=None, *args, **kwargs):
    
        formdata = request.form
        self.request = request

        csrf_enabled = kwargs.pop('csrf_enabled', None)
        if not self.csrf_enabled:
            self.csrf_enabled = self.request.csrf_enabled

        self.csrf_session_key = kwargs.pop('csrf_session_key', None)
        if not self.csrf_session_key:
            self.csrf_session_key = request.csrf_session_key
        csrf_token = self.request.session.get(self.csrf_session_key, None)

        if csrf_token is None:
            csrf_token = self.reset_csrf()

        super(Form, self).__init__(formdata, csrf=csrf_token, *args, **kwargs)

    def is_submitted(self):
        return self.request and self.request.method in ("PUT", "POST")

    def process(self, formdata=None, obj=None, **kwargs):

        if self.is_submitted():
        
            if formdata is None:
                formdata = self.request

            # ensure csrf validation occurs ONLY when formdata is passed
            # in case "csrf" is the only field in the form

            if not formdata and not self.request.files:
                self.csrf_is_valid = False
            else:
                self.csrf_is_valid = None

        super(Form, self).process(formdata, obj, **kwargs)

    @property
    def csrf_token(self):
        """
        Renders CSRF field inside a hidden DIV.

        :deprecated: Use **hidden_tag** instead.
        """
        warnings.warn("csrf_token is deprecated. Use hidden_tag instead", 
                      DeprecationWarning)

        return self.hidden_tag('csrf')

    def reset_csrf(self):
        """
        Resets the CSRF token in the session. If you are reusing the form
        in the same view (i.e. you are not redirecting somewhere else)
        it's recommended you call this before rendering the form.
        """
        
        csrf_token = _generate_csrf_token()
        self.request.session[self.csrf_session_key] = csrf_token
        return csrf_token

    def validate_csrf(self, field):
        if not self.csrf_enabled:
            return

        csrf_token = self.request.session.pop(self.csrf_session_key, None)
        is_valid = field.data and \
                   field.data == csrf_token and \
                   self.csrf_is_valid is not False

        # reset this field, otherwise stale token is displayed
        field.data = self.reset_csrf()

        # we set this flag to ensure consistent behaviour when
        # calling validate() more than once

        self.csrf_is_valid = bool(is_valid)

        if not is_valid:
            raise ValidationError, "Missing or invalid CSRF token"

    def hidden_tag(self, *fields):
        """
        Wraps hidden fields in a hidden DIV tag, in order to keep XHTML 
        compliance.

        .. versionadded:: 0.3

        :param fields: list of hidden field names. If not provided will render
                       all hidden fields, including the CSRF field.
        """

        if not fields:
            fields = [f for f in self if isinstance(f, HiddenField)]

        rv = [u'<div style="display:none;">']
        for field in fields:
            if isinstance(field, basestring):
                field = getattr(self, field)
            rv.append(unicode(field))
        rv.append(u"</div>")

        return u"".join(rv)
        
    def validate_on_submit(self):
        """
        Checks if form has been submitted and if so runs validate. This is 
        a shortcut, equivalent to ``form.is_submitted() and form.validate()``
        """
        return self.is_submitted() and self.validate()
        
    is_valid = validate_on_submit
    

##-----------html5 fileds----------
class html5(object):
    """html5 fields' module"""

class DateInput(Input):
    """
    Creates `<input type=date>` widget
    """
    input_type = "date"

class NumberInput(Input):
    """
    Creates `<input type=number>` widget
    """
    input_type="number"

class RangeInput(Input):
    """
    Creates `<input type=range>` widget
    """
    input_type="range"

class URLInput(Input):
    """
    Creates `<input type=url>` widget
    """
    input_type = "url"

class EmailInput(Input):
    """
    Creates `<input type=email>` widget
    """
    input_type = "email"

class SearchInput(Input):
    """
    Creates `<input type=search>` widget
    """
    input_type = "search"

#fields
class SearchField(TextField):
    """
    **TextField** using **SearchInput** by default
    """
    widget = SearchInput()
html5.SearchField = SearchField

class DateField(_DateField):
    """
    **DateField** using **DateInput** by default
    """
    widget = DateInput()
html5.DateField = DateField

class URLField(TextField):
    """
    **TextField** using **URLInput** by default
    """
    widget = URLInput()
html5.URLField = URLField

class EmailField(TextField):
    """
    **TextField** using **EmailInput** by default
    """
    widget = EmailInput()
html5.EmailField = EmailField

class IntegerField(_IntegerField):
    """
    **IntegerField** using **NumberInput** by default
    """
    widget = NumberInput()
html5.IntegerField = IntegerField

class DecimalField(_DecimalField):
    """
    **DecimalField** using **NumberInput** by default
    """
    widget = NumberInput()
html5.DecimalField = DecimalField

class IntegerRangeField(_IntegerField):
    """
    **IntegerField** using **RangeInput** by default
    """
    widget = RangeInput()
html5.IntegerRangeField = IntegerRangeField

class DecimalRangeField(_DecimalField):
    """
    **DecimalField** using **RangeInput** by default
    """
    widget = RangeInput()
html5.DecimalRangeField = DecimalRangeField
###-----------end html5 fields----------

###-----------file fields---------------

class FileField(_FileField):
    """
    Subclass of **wtforms.FileField** providing a `file` property
    """
    @property
    def file(self):
        """
        Returns FileStorage class if available from .files
        or None
        """
        return self.request.files.get(self.name, None)

class FileRequired(object):
    """
    Validates that field has a **FileStorage** instance
    attached.

    `message` : error message

    You can also use the synonym **file_required**.
    """

    def __init__(self, message=None):
        self.message=message

    def __call__(self, form, field):
        file = getattr(field, "file", None)

        if not file:
            raise ValidationError, self.message

file_required = FileRequired



fields.FileField = FileField

validators.file_required = file_required
validators.FileRequired = FileRequired
###-----------end file fields-----------------
