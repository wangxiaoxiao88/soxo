#!/usr/bin/env python
#coding=utf-8

"""
    perm.py
    ~~~~~~~~~~~~~
    
    permission extension
    :license: BSD
"""

from functools import wraps

class Role(object):
    def __init__(self, name):
        self.name = name
    def __eq__(self, other):
        return self.name == other.name
        
class Identity(object):

    def __init__(self, permission, http_exception=None):
        self.permission = permission
        self.http_exception = http_exception

    def __call__(self, f):
        @wraps(f)
        def _decorated(*args, **kw):
            role = self.valid()#self.valid.func_globals.update(request, session)
            if self.permission.can(role)
                res = f(*args, **kw)#clear_g(self.valid, ~)
                return res
            else:
                raise Exception(self.http_exception)
        return _decorated
        
    def valid(self):pass
        
class Permission(object):
    def __init__(self, *roles):
        self.needs = set(roles)

    def require(self, http_exception=None):
        return Identity(self, http_exception)
        
    def can(self, role):
        return role in self.needs
