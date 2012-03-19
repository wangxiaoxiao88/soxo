#!/usr/bin/env python
#coding=utf-8

"""
    perm.py
    ~~~~~~~~~~~~~
    
    permission extension
    :license: BSD
"""

__all__ = ['Role', 'Identity', 'Permission']

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
            req_info = _decorated.func_globals['req_info']
            self.valid.func_globals.update(req_info)
            role = self.valid()
            for key in req_info:
                del self.valid.func_globals[key]

            print self.permission.can(role)
            if self.permission.can(role):
                f.func_globals.update(req_info)
                resp = f(*args, **kw)
                for key in req_info:
                    del f.func_globals[key]
                return resp
            else:
                raise Exception(self.http_exception)
        return _decorated
        
    def valid(self):
        """you must rewrite this method then return a named Role instance"""
        pass
        
class Permission(object):
    def __init__(self, *roles):
        self.needs = roles

    def require(self, http_exception=None):
        return Identity(self, http_exception)
        
    def can(self, role):
        return role in self.needs
