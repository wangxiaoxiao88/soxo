#!/usr/bin/env python
#coding=utf-8

"""
    sqla.py
    ~~~~~~~~~~~~~
    
    sqlalchemy extension
    :license: BSD
"""
import re
from functools import partial
import sqlalchemy
from sqlalchemy import orm, types
from sqlalchemy.orm.mapper import Mapper
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.interfaces import MapperExtension, SessionExtension, \
     EXT_CONTINUE
from sqlalchemy.orm.exc import UnmappedClassError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.util import to_list

_camelcase_re = re.compile(r'([A-Z]+)(?=[a-z0-9])')

def _create_scoped_session(db, options):
    if options is None:
        options = {}
    return orm.scoped_session(partial(_SignallingSession, db, **options))


def _make_table(db):
    def _make_table(*args, **kwargs):
        if len(args) > 1 and isinstance(args[1], db.Column):
            args = (args[0], db.metadata) + args[1:]
        return sqlalchemy.Table(*args, **kwargs)
    return _make_table


def _include_sqlalchemy(obj):
    for module in sqlalchemy, sqlalchemy.orm:
        for key in module.__all__:
            if not hasattr(obj, key):
                setattr(obj, key, getattr(module, key))
    obj.Table = _make_table(obj)


class _SignallingSession(Session):

    def __init__(self, db, autocommit=False, autoflush=False, **options):
        Session.__init__(self, autocommit=autocommit, autoflush=autoflush,
                         bind=db.engine, **options)


class _QueryProperty(object):

    def __init__(self, sa):
        self.sa = sa

    def __get__(self, obj, type):
        try:
            mapper = orm.class_mapper(type)
            if mapper:
                return type.query_class(mapper, session=self.sa.session())
        except UnmappedClassError:
            return None


class _SignalTrackingMapper(Mapper):
    def __init__(self, *args, **kwargs):
        extensions = to_list(kwargs.pop('extension', None), [])
        kwargs['extension'] = extensions
        Mapper.__init__(self, *args, **kwargs)


class _ModelTableNameDescriptor(object):

    def __get__(self, obj, type):
        tablename = type.__dict__.get('__tablename__')
        if not tablename:
            def _join(match):
                word = match.group()
                if len(word) > 1:
                    return ('_%s_%s' % (word[:-1], word[-1])).lower()
                return '_' + word.lower()
            tablename = _camelcase_re.sub(_join, type.__name__).lstrip('_')
            setattr(type, '__tablename__', tablename)
        return tablename

class Pagination(object):
    """Internal helper class returned by :meth:`BaseQuery.paginate`.  You
    can also construct it from any other SQLAlchemy query object if you are
    working with other libraries.  Additionally it is possible to pass `None`
    as query object in which case the :meth:`prev` and :meth:`next` will
    no longer work.
    """

    def __init__(self, query, page, per_page, total, items):
        #: the unlimited query object that was used to create this
        #: pagination object.
        self.query = query
        #: the current page number (1 indexed)
        self.page = page
        #: the number of items to be displayed on a page.
        self.per_page = per_page
        #: the total number of items matching the query
        self.total = total
        #: the items for the current page
        self.items = items

    @property
    def pages(self):
        """The total number of pages"""
        return int(ceil(self.total / float(self.per_page)))

    def prev(self, error_out=False):
        """Returns a :class:`Pagination` object for the previous page."""
        assert self.query is not None, 'a query object is required ' \
                                       'for this method to work'
        return self.query.paginate(self.page - 1, self.per_page, error_out)

    @property
    def prev_num(self):
        """Number of the previous page."""
        return self.page - 1

    @property
    def has_prev(self):
        """True if a previous page exists"""
        return self.page > 1

    def next(self, error_out=False):
        """Returns a :class:`Pagination` object for the next page."""
        assert self.query is not None, 'a query object is required ' \
                                       'for this method to work'
        return self.query.paginate(self.page + 1, self.per_page, error_out)

    @property
    def has_next(self):
        """True if a next page exists."""
        return self.page < self.pages

    @property
    def next_num(self):
        """Number of the next page"""
        return self.page + 1

    def iter_pages(self, left_edge=2, left_current=2,
                   right_current=5, right_edge=2):
        """Iterates over the page numbers in the pagination.  The four
        parameters control the thresholds how many numbers should be produced
        from the sides.  Skipped page numbers are represented as `None`.
        This is how you could render such a pagination in the templates:

        .. sourcecode:: html+jinja

            {% macro render_pagination(pagination, endpoint) %}
              <div class=pagination>
              {%- for page in pagination.iter_pages() %}
                {% if page %}
                  {% if page != pagination.page %}
                    <a href="{{ url_for(endpoint, page=page) }}">{{ page }}</a>
                  {% else %}
                    <strong>{{ page }}</strong>
                  {% endif %}
                {% else %}
                  <span class=ellipsis>…</span>
                {% endif %}
              {%- endfor %}
              </div>
            {% endmacro %}
        """
        last = 0
        for num in xrange(1, self.pages + 1):
            if num <= left_edge or \
               (num > self.page - left_current - 1 and \
                num < self.page + right_current) or \
               num > self.pages - right_edge:
                if last + 1 != num:
                    yield None
                yield num
                last = num
                
class BaseQuery(orm.Query):
    """The default query object used for models.  This can be subclassed and
    replaced for individual models by setting the :attr:`~Model.query_class`
    attribute.  This is a subclass of a standard SQLAlchemy
    :class:`~sqlalchemy.orm.query.Query` class and has all the methods of a
    standard query as well.
    """

    def get_or_404(self, ident):
        """Like :meth:`get` but aborts with 404 if not found instead of
        returning `None`.
        """
        rv = self.get(ident)
        if rv is None:
            return 404
        return rv

    def first_or_404(self):
        """Like :meth:`first` but aborts with 404 if not found instead of
        returning `None`.
        """
        rv = self.first()
        if rv is None:
            return 404
        return rv

    def paginate(self, page, per_page=20, error_out=True):
        """Returns `per_page` items from page `page`.  By default it will
        abort with 404 if no items were found and the page was larger than
        1.  This behavor can be disabled by setting `error_out` to `False`.

        Returns an :class:`Pagination` object.
        """
        if error_out and page < 1:
            return 404
        items = self.limit(per_page).offset((page - 1) * per_page).all()
        if not items and page != 1 and error_out:
            return 404
        return Pagination(self, page, per_page, self.count(), items)


class Model(object):
    """Baseclass for custom user models."""

    #: the query class used.  The :attr:`query` attribute is an instance
    #: of this class.  By default a :class:`BaseQuery` is used.
    query_class = BaseQuery

    #: an instance of :attr:`query_class`.  Can be used to query the
    #: database for instances of this model.
    query = None

    #: arguments for the mapper
    __mapper_cls__ = _SignalTrackingMapper

    __tablename__ = _ModelTableNameDescriptor()

class SQLAlchemy(object):
    """
        sqlalchemy, db.set_model(SomeModel:db.Model)
                    db.get_model('SomeModel')
                    db.create_all()
                    db.drop_all()
    """
    def __init__(self, engine_url, echo=False,
                 session_extensions=None, session_options=None):
        """Init""" 
        self.session = _create_scoped_session(self, session_options)
        self.Model = declarative_base(cls=Model, name='Model')
        self.Model.query = _QueryProperty(self)
        self.engine = sqlalchemy.create_engine(engine_url, echo=echo)
        _include_sqlalchemy(self)
        
        #for get_model
        self.__models_set = {}
        self.BaseQuery = BaseQuery

    def create_all(self):
        """Creates all tables."""
        self.Model.metadata.create_all(bind=self.engine)

    def drop_all(self):
        """Drops all tables."""
        self.Model.metadata.drop_all(bind=self.engine)
        
    def set_model(self, cls):
        self.__models_set[cls.__name__] = cls
        
    def get_model(self, name):
        """通过名称来获得Model类，Model类定义完需: db.set_model(cls)来预存Model类"""
        return self.__models_set.get(name, None)


class DenormalizedText(types.MutableType, types.TypeDecorator):
    """
    Stores denormalized primary keys that can be 
    accessed as a set. 

    :param coerce: coercion function that ensures correct
                   type is returned

    :param separator: separator character
    """

    impl = types.Text

    def __init__(self, coerce=int, separator=",", **kwargs):

        self.coerce = coerce
        self.separator = separator
        
        super(DenormalizedText, self).__init__(**kwargs)

    def process_bind_param(self, value, dialect):
        if value is not None:
            items = [str(item).strip() for item in value]
            value = self.separator.join(item for item in items if item)
        return value

    def process_result_value(self, value, dialect):
         if not value:
            return set()
         return set(self.coerce(item) \
                   for item in value.split(self.separator))
        
    def copy_value(self, value):
        return set(value)
