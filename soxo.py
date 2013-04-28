#coding=utf-8
"""a micro flask like python web framework, see README for more infomation"""
__all__ = ['Module', 'Soxo', 'BaseView', 'cached_property', 'url_for', 'render', 'redirect']

import re, os, sys, pickle, os.path
import hashlib, time, base64
from urllib import urlencode
from urlparse import parse_qs

from sys import exc_info
from traceback import format_tb
from uuid import uuid4
from Cookie import SimpleCookie
from utils.multipart import parse_form_data

from jinja2 import Environment, PackageLoader

#静态文件服务器，可以在开发的时候用下, debug开启
class FileServerMiddleware(object):
    ext_to_mimetype = {
        '.html': 'text/html', ".htm": "text/html",
        '.jpeg': 'image/jpeg', '.jpg': 'image/jpeg', ".gif": "image/gif",'.ico':'image/ico', '.png':'image/png',
        ".uu":  "application/octet-stream", ".exe": "application/octet-stream",
        ".ps":  "application/postscript", ".zip": "application/zip",
        ".sh":  "application/x-shar", ".tar": "application/x-tar", ".wav": "audio/x-wav",
        '.pdf': 'application/pdf', ".snd": "audio/basic", ".au": "audio/basic",
        '.css': 'text/css', '.txt': 'text/plain', ".c": "text/plain", ".cc": "text/plain",
        ".cpp": "text/plain", ".h": "text/plain", ".pl": "text/plain", ".java": "text/plain",'.js':'text/javascript'
    }
    def __init__(self, application, path, prefix='/static', BLOCK_SIZE=12288):
        self.path = path
        self.prefix = prefix
        self.application = application
        self.BLOCK_SIZE = BLOCK_SIZE
        
    def __call__(self, environ, start_response):
        path_info = environ["PATH_INFO"]
        ext = os.path.splitext(path_info)[1].lower()
        if not path_info or not ext:
            return self.application(environ, start_response)

        file_path = os.path.join(self.path, path_info[len(self.prefix):].lstrip('/'))
        # 404 not found
        if not os.path.isfile(file_path):
            start_response("404 NOT FOUND", [("Content-type", "text/plain")])
            return ["Not found",]
        # 403 forbidden
        mimetype = FileServerMiddleware.ext_to_mimetype.get(ext, None)
        if not mimetype:
            start_response("403 FORBIDDEN", [("Content-type", "text/plain")])
            return ["Forbidden",]
        # send headers & file
        headers = [("Content-Type", mimetype), 
                ("Content-length", str(os.path.getsize(file_path)))]
        start_response("200 OK", headers)
        return self._send_file(file_path)

    def _send_file(self, file_path):
        with open(file_path,'rb') as f:
            block = f.read(self.BLOCK_SIZE)
            while block:
                yield block 
                block = f.read(self.BLOCK_SIZE)

#很挫的错误显示中间件
class HttpError(object):
    def __init__(self, status=200, msg='', exc_info=None, request=None):
        self.status = status
        self.msg = msg
        self.exc_info = exc_info
        self.request = request

class Redirect(HttpError):
    def __init__(self, status, location):
        self.status = status
        self.location = location

def redirect(location, code=302):
    assert code in (201, 301, 302, 303, 305, 307), 'invalid code'
    if code == 301:
        code = '301 Moved Permanently'
    elif code == 302:
        code = '302 Found'
    return Redirect(code, location)

class ExceptionMiddleware(object):
    def __init__(self, app):
        self.app = app
        self.stack = []#record traceback, max 500 items
        self.htmls = """<html><head><title>ERROR DEBUG</title><style>a{text-decoration:none;}</style><script src='http://ajax.googleapis.com/ajax/libs/jquery/1.8.0/jquery.min.js'></script></head><body>%s</body><script>$(function(){$('input').hide();$('a').live('click', function(e){e.preventDefault();$('input').hide();$(this).siblings('input').show().focus();});$('input').live('keyup',function(e){if(e.keyCode==13){var tar=$(this), href=tar.siblings('a').attr('href');$.get(href+tar.val(), function(json){tar.siblings('span').html(json);})}});})</script></html>"""
    def __call__(self, environ, start_response):
        """Call the application can catch exceptions."""
        args = QueryString(environ["QUERY_STRING"])
        if args.get('__debug', ''):
            src, frameid = args.get('code', ''), args.get('frame', 0)
            if src and frameid:
                tb = filter(lambda x: id(x[0])==int(frameid), self.stack)
                fr = tb[0][0].tb_frame
                try:
                    fr.f_locals.update({'request':tb[0][1]})
                    res = eval(src, fr.f_globals, fr.f_locals)
                except Exception as e:res = str(e)
                start_response("200 OK", [("Content-type", "text/html")])
                res = unicode(res).encode('utf8').replace('>', '&gt;').replace('<', '&lt;')
                return res

        appiter = self.app(environ, start_response)
        if type(appiter) is HttpError:
            traceback = ['<dl><dt>Traceback (most recent call last):']
            traceback.append(appiter.msg+'</dt><dd><ul>')
            path = environ.get('PATH_INFO', '')
            if appiter.exc_info:
                e_type, e_value, tb = appiter.exc_info
                e_type = str(e_type)
                e_type = e_type.replace('>', '&gt;').replace('<', '&lt;')
                tb_f_list, tb_list,  = format_tb(tb), []
                while tb:
                    tb_list.append((tb, appiter.request))
                    _ftb, _tb = tb_f_list.pop(0), ['<li>']
                    _ftb.replace('>', '&gt;').replace('<', '&lt;')
                    _tb.append(_ftb[:-1])
                    _tb.append('<a href="%s?__debug=1&frame=%d&code=">&gt;_</a><br/>' % (path, id(tb)))
                    _tb.append('<span style="background-color:#eee;width:600px;display:block;"></span><input type="text" style="width:600px;"/></li>')
                    traceback.append(''.join(_tb))
                    tb = tb.tb_next
            traceback.append('</ul><br/>%s: %s</dd></dl>' % (e_type, e_value))

            if len(self.stack) >= 500:
                self.stack = self.stack[10:]
            self.stack = self.stack + tb_list
            start_response("500 Internal Server Error", [("Content-type", "text/html")])
            return [self.htmls % (''.join(traceback).replace('\n', '<br/>'))]
        return ''.join(appiter)

#url_arg_parse
def url_arg_parse(origin):
    args = [argstr.lstrip('<').rstrip('>').split(':') for argstr in re.findall('<[^<>]*>', origin)]
    url = re.split('<[^<>]+>', origin)
    modfunc_url = url[:]
    for t, i in enumerate(args):
        if len(i) == 2:
            if i[0] == 'str':
                url[t] = url[t] + '(?P<'+i[-1] + '>[^/]+)'
            elif i[0] == 'int':
                url[t] = url[t] + '(?P<'+i[-1] + r'>\d+)'
            elif i[0] == 'float':
                url[t] = url[t] + '(?P<'+i[-1] + r'>\d*\.\d+)'
            else:
                url[t] = url[t] + '(?P<'+i[-1] + '>.*)'
                #path
                args[t][0] = 'str'
        else:
            url[t] = url[t] + '(?P<'+i[-1] + '>[^/]*)'
            args[t].insert(0, 'str')
        modfunc_url[t] = modfunc_url[t] + '%('+ i[-1] + ')s'
    return '^'+"".join(url)+'$', dict([ (i[1], i[0]) for i in args]), ''.join(modfunc_url)

#request Global object
class G(dict):
    def __init__(self, *args, **kwargs):
        super(G, self).__init__(*args, **kwargs)
        self.__dict__ = self

    def __getattr__(self, key):
        return None

    def get(self, key, _type=None):
        return _type(super(G, self).get(key)) if _type else super(G, self).get(key)

    def _get(self, key, default):
        val = self.get(key)
        if val is None:
            val = default
        return val

    def getlist(self, key, _type=None):
        val = super(G, self).get(key)
        val = val if type(val) is list else ([val] if val is not None else [])
        return [_type(i) for i in val] if _type else val

    def _getlist(self, key, default):
        val = self.getlist(key)
        if not val:
            val = default
        return val

#cached_property, user's function
class cached_property(object):
    def __init__(self, func):
        self.func = func
    def __get__(self, obj, cls):
        if obj is None: return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value

#hmac encrypt function, for session secret
def encrypt(strs, is_encrypt = 1, key = 'soxo'): 
    dynkey = hashlib.new('sha1', str(time.time())).hexdigest() if is_encrypt == 1 else strs[0:40] 
    dykey1 = dynkey[0:20] 
    dykey2 = dynkey[20:] 
  
    fixnkey = hashlib.new('sha1', key).hexdigest() 
    fixkey1 = fixnkey[0:20] 
    fixkey2 = fixnkey[20:] 
 
    newkey = hashlib.new('sha1', dykey1 + fixkey1 + dykey2 + fixkey2).hexdigest()
 
    if(is_encrypt == 1): 
        newstr = fixkey1 + strs + dykey2 
    else:  
        newstr = base64.b64decode(strs[40:].replace('_', '=')) 
 
    re = '' 
    strlen = len(newstr) 
    for i in range(0, strlen): 
        j = i % 40 
        re += chr(ord(newstr[i]) ^ ord(newkey[j])) 
  
    return dynkey + base64.b64encode(re).replace('=', '_') if is_encrypt == 1 else re[20:-20] 

#query_str，session，request，每次请求都是重建的
def QueryString(qstr):
    qs = parse_qs(qstr)
    for k, v in qs.items():
        if len(v) == 1:
            qs[k] = v[0]
    return G(**qs)

#session
class Session(dict):
    def __init__(self, rs=None, secret_key='soxo', cookie=None, expires=1800*4):#two hours
        self.rs = rs
        self.cookie = cookie
        self.expires = expires
        self.secret_key = secret_key
        #store in cookie
        if not self.rs:
            if self.cookie.has_key('__soxo_session_id'):
                self.sessionID = 'soxo_session_cookie_store'
                try:
                    self.data = pickle.loads( encrypt( \
                            str(self.cookie["__soxo_session_id"].value), 0, key=self.secret_key \
                            ))
                except:
                    self.data = {}
            else:
                self.data = {}
        #store in redis
        else:
            if self.cookie.has_key('__soxo_session_id'):
                self.sessionID = self.cookie["__soxo_session_id"].value
            else:
                self.sessionID = str(uuid4())
            _s = self.rs.get(self.sessionID)
            self.data = pickle.loads(str(_s)) if _s else {}
            
    def set_expires(self, expires=None):
        self.cookie["__soxo_session_id"]['expires'] = expires if expires else self.expires
        if self.rs:
            self.rs.expire(self.sessionID, expires if expires else self.expires)
        
    def __getitem__(self,key):
        return self.get(key)
    
    def get(self, key, default=None):
        self.set_expires()
        return self.data.get(key, default)
    
    def __setitem__(self,key,value):
        self.data[key] = value
        self.save()

    def id(self,key):
        self.sessionID
    
    def __delitem__(self,key):
        if key in self.data:
            del self.data[key]
            self.save()
        
    def pop(self, key, default=None):
        data = self.data.get(key, default)
        del self[key]
        return data
        
    def clear(self):
        self.data = {}
        self.save()
        
    def save(self):
        if self.rs:
            self.rs.set(self.sessionID, pickle.dumps(self.data))
            self.cookie["__soxo_session_id"] = self.sessionID
        else:
            self.cookie["__soxo_session_id"] = encrypt(pickle.dumps(self.data), 1, key = self.secret_key)
        self.set_expires()

#request obj
class Request(object):
    def __init__(self,environ, server_name):
        self.method = environ.get("REQUEST_METHOD","")
        self.form, self.files = parse_form_data(environ)
        path = environ.get('PATH_INFO', '')
        self.path = path if path.endswith('/') else path + '/'
        self.server_name = environ.get('SERVER_NAME', '')

        self.subdomain = self.server_name.replace(server_name, '')
        self.subdomain = self.subdomain[:-1] if self.subdomain.endswith('.') else self.subdomain
        self.subdomain = '' if self.subdomain == 'www' else self.subdomain
        
        self.is_ajax = self.is_xhr = environ.get('HTTP_X_REQUESTED_WITH','').lower() == 'xmlhttprequest'
        self.is_post, self.is_get = self.method == 'POST', self.method == 'GET'
                
        self.status = "200 0k"
        self.headers = []
        self.env = self.environ = environ
        
    def save2file(self,name,path):
        with file(path,'wb') as f:
            f.write(self.files.get(name).read())
        return True

#base view
class BaseView(object):
    def __call__(self, *args, **kwargs):
        method = self.request.method.lower()
        if not hasattr(self, method):
            return HttpError(status=405, msg=method+' not allow!')
        return getattr(self, method)(*args, **kwargs)
    def _request(self, request):
        self.request = request
        self.qstr = request.qstr
        self.cookie = request.cookie
        self.session = request.session
        self.g = request.g
        self.config = request.config
        self.environ = request.environ

#app and module
SOXO_MODULE, MODULES = None, []
URLS = {}
TPL_ENV = None

def render(tpl='', **kw):
    kw['url_for'] = url_for
    kw['redirect'] = redirect
    template = TPL_ENV.get_template(tpl)
    return template.render(**kw)

def url_for(modfunc, **args):
    """only usable when Soxo instance inited"""
    url_rules = []
    mod, func = modfunc.split('.')
    prefix_url = ''
    for prefix, module in MODULES:
        if module.module == mod:
            url_rules = URLS[module.module]
            prefix_url = prefix
            break
    else:
        url_rules = URLS[SOXO_MODULE.module]
    #所有的module匹配的rule
    match_rules = filter(lambda rule: modfunc==rule[1]['module'], url_rules)
    if not match_rules:
        raise Exception, "Can't reverse route of :"+modfunc
    #url参数匹配最多那个match_rule
    if not args:
        rule = filter(lambda m: not m[1]['args'], match_rules)[0]
    else:
        rules = filter(lambda m: m[1]['args'].keys()==args.keys(), match_rules)
        if not rules:
            arg_counts = [len( filter(lambda arg: arg in m[1]['args'], args)) for m in match_rules]
            if min(arg_counts) == max(arg_counts):#if equal match url args, args'length less is better
                arg_counts = [len(m[1]['args']) for m in match_rules]
                rule = match_rules[arg_counts.index(min(arg_counts))]
            else:
                rule = match_rules[arg_counts.index(max(arg_counts))]
        else:
            rule = rules[0]

    qs, reverse = {}, rule[1]['reverse_route']
    for k in args.keys():
        if k not in rule[1]['args']:
            qs[k] = args[k].encode('utf8') if type(args[k]) is unicode else str(args[k])
            del args[k]
    try:
        url = prefix_url if mod else ''
        return url + reverse % args + '?' + urlencode(qs) if qs else url + reverse % args
    except:
        return HttpError(status=500, msg='%s\'s arguments err------past args are %s: \n' + \
                'accept args are %s' % (modfunc, str(args), str(rule[1]['args'])))

class Module(object):
    def __init__(self, name=''):
        self.module = name if name else self.__name__
        self.handlers = {}
        URLS[self.module] = []
        
    def add_url_rule(self, rule, f):
        pattern, args, modfunc_url = url_arg_parse(rule)
        URLS[self.module].append((pattern, \
                {'args':args, 'reverse_route':modfunc_url, 'callback':f, \
                'module':self.module+'.'+f.__name__
                }))
    
    def route(self, rule):
        def decorator(f):
            self.add_url_rule(rule, f)
            return f
        return decorator
    
    def invoke_handler(self, key, handlers, request):
        handler = self.handlers.get(key, None) or handlers.get(key, None)
        if handler:
            return handler(request)
    
    def arg_type_convert(self, args, types):
        for k in args.keys():
            if types[k] == 'int':
                args[k] = int(args[k])
            elif types[k] == 'float':
                args[k] = float(args[k])
        return args
        
    def url_dispatch(self, path, request, handlers={}):
        # 最少args的优先, /login/ first than /<opt>/
        match_rules= filter(lambda x: re.search(x[0], path), URLS[self.module][::-1])
        rule = None
        if not match_rules:
            resp = self.invoke_handler('error404_handler', handlers, request)
            if not resp:
                return HttpError(status=404, msg='404 NO FOUND', request=request)
            return resp
        elif len(match_rules) == 1:
            rule = match_rules[0]
        else:
            arg_counts = [len( m[1]['args']) for m in match_rules]
            rule = match_rules[arg_counts.index(min(arg_counts))]
        cb_dict = rule[1]
        match = re.search(rule[0], path)

        #get url args
        args = match.groupdict()
        self.arg_type_convert(args, cb_dict['args'])
        #if has before_handler
        self.invoke_handler('before_handler', handlers, request)
        #class view enable
        callback = cb_dict['callback']()
        callback._request(request)
        #response
        try:
            resp = callback(**args)
        except Exception as e:
            if request.config.debug:
                resp = HttpError(status=500, msg=e.message, exc_info=exc_info(), request=request)
            else:
                resp = self.invoke_handler('error500_handler', handlers, request)
                if not resp:
                    resp = HttpError(status=500, msg='500 SERVER ERROR', exc_info=exc_info(), request=request)
        finally:
            #if has after_handler
            self.invoke_handler('after_handler', handlers, request)
        return resp

    def before_request(self):
        def decorator(f):
            self.handlers['before_handler'] = f
            return f
        return decorator

    def after_request(self):
        def decorator(f):
            self.handlers['after_handler'] = f
            return f
        return decorator

    def error_404(self):
        def decorator(f):
            self.handlers['error404_handler'] = f
            return f
        return decorator

    def error_500(self):
        def decorator(f):
            self.handlers['error500_handler'] = f
            return f
        return decorator

class Soxo(Module):
    def __init__(self, config=None):
        self.url_prefix = ''
        self.debug = False
        self.module = ''
        
        URLS[self.module] = []#!self.url_rules = []
        self.handlers = {}

        self.config = G()
        if config:
            self.config.__dict__.update(config)

        self.tpl_env = Environment(loader=PackageLoader( \
                self.config._get('template_dir', 'templates'), ''))
        global TPL_ENV
        TPL_ENV = self.tpl_env
        global SOXO_MODULE
        SOXO_MODULE = self
        
    def register_filter(self, name):
        """注册一个过滤器"""
        def decorator(f):
            self.tpl_env.filters[name] = f
        return decorator
            
    def url_dispatch(self, path, request):
        empty_prefix, empty_prefix_module = None, None#path='/', prefix_url=''
        match_modules = []
        for prefix_url, module in MODULES:
            #subdomain match
            if module.subdomain and request.subdomain == module.subdomain:
                #subdomain support multi module
                if path.startswith(prefix_url):
                    return module.url_dispatch(path.replace(prefix_url, '', 1), request, handlers=self.handlers)
            elif not prefix_url:
                empty_prefix, empty_prefix_module = prefix_url, module
                continue
            #prefix_url match
            elif path.startswith(prefix_url):
                match_modules.append((prefix_url, module))

        if match_modules:
            prefix_url, module = max(match_modules, key=lambda o: len(o[0]))
            return module.url_dispatch(path.replace(prefix_url, '', 1), request, handlers=self.handlers)
        if empty_prefix_module:
            return empty_prefix_module.url_dispatch(path, request, handlers=self.handlers)
        return super(Soxo, self).url_dispatch(path, request)
        
    def __call__(self, environ, start_response):
        """wsgi wrapper"""
        request = Request(environ, self.config._get('domain', ''))
        request.g = G()
        request.config = self.config
        request.qstr = QueryString(environ["QUERY_STRING"])
        request.cookie = SimpleCookie(environ.get("HTTP_COOKIE",""))
        request.session = Session(rs=self.config.get('redis'), \
                secret_key=self.config._get('csrf_session_key', ''), \
                cookie=request.cookie, expires=self.config._get('session_expires', 0))
        #handle dispatch
        resp = self.url_dispatch(request.path, request)
        #cookie handle
        if (len(request.cookie)!=0):
            for k, v in request.cookie.items():
                if '__utm' not in str(v):
                    if not v['path']:
                        v['path'] = '/'
                    if not v['expires']:
                        v['expires'] = self.config._get('cookie_expires', 0)
                request.headers.append( ('Set-Cookie', str(v).split(': ')[1]) )
        #handle redirect
        if type(resp) is Redirect:
            request.status = resp.status
            request.headers.append(('Location', resp.location))
            resp = ''
        elif type(resp) is HttpError:
            return resp
        #start resp
        request.headers.append(("Content-type", "text/html"))
        start_response(request.status, request.headers)
        if type(resp) is str:
            return resp
        elif type(resp) is unicode:
            return resp.encode('utf8')
        return ''.join([r.encode('utf8') for r in resp])

    def register_module(self, prefix_url, module, subdomain=''):
        module.subdomain = subdomain
        MODULES.append((prefix_url, module))
        
    def run(self, host='localhost', port=9000):
        from gevent.pywsgi import WSGIServer
        #debug mode can serve static file and check trace
        app = self
        if self.debug:
            app = FileServerMiddleware(app, self.config._get('static', ''))
            app = ExceptionMiddleware(app)
        WSGIServer((host, port), app).serve_forever()

def run_devserver():
    """just for dev"""
    from subprocess import Popen as popen
    filename = sys.argv[1]
    if not filename:
        print 'use command like: python soxo.py ./wsgi.py'
        exit(0)
    begin_time = time.time()
    dirname = os.path.dirname(filename)
    dirname = './' if not dirname else dirname
    def is_file_modify(dirname):
        for fl in os.walk(dirname):
            for f in [f for f in fl[-1] if os.path.splitext(f)[1] == '.py']:
                if '_html' not in f and os.stat(fl[0]+'/'+f).st_mtime > begin_time:
                    return True
    #watcher
    while True:
        p = popen(['python', filename])
        try:
            while True:#True:
                #if any file change, reload
                if is_file_modify(dirname):
                    p.terminate()
                    begin_time = time.time()
                    print ('some file change, server reloading...')
                    break
                time.sleep(0.01)
        except KeyboardInterrupt:
            p.terminate()
            print ('\nterminate %s' % str(p))
            exit(0)
                
if __name__ == "__main__":
    run_devserver()##cA5dR6Hn6kU6