#coding=utf-8
"""a micro flask like python web framework, see README for more infomation"""
__all__ = ['Template', 'Module', 'Soxo', 'BaseView', 'cached_attr', 'cached_property']

import re, os, sys, pickle, os.path, cgi
import gzip
import inspect
from cStringIO import StringIO
from urllib import urlencode

from sys import exc_info
from traceback import format_tb

from uuid import uuid4
from Cookie import SimpleCookie
from types import FunctionType as fn_type
#the only ref:: parse_form_data(environ, charset='utf8', strict=False, **kw):
from utils.multipart import parse_form_data 

#########################################################################
######简单模板系统代码------支持filter，extends，include， 和一些复杂表达式
class Template(object):
    #{%%} tag
    delimiter = re.compile(r"\{\%\s?(.*?)\s?\%\}")
    #val echo pattern
    echo_pattern_jinja2 = re.compile(r"(\{\{.*?\}\})")
    echo_val_pattern_jinja2 = re.compile(r"\{\{\s?(.*?)\s?\}\}")
    #tag have endtag
    __TAG__ = (re.compile('\s?if'), re.compile('\s?for'),)
    #end tag
    __END_TAG__ = ( re.compile('\s?endif'), re.compile('\s?endfor'),)
    __end_tag__ = ('endif', 'endfor',)
    #elif,else
    __ELIF_ELSE__ = (re.compile('\s?elif'), re.compile('\s?else'),)
    #extend pattern
    extend_pattern = re.compile(r"""\{\%\s?extends\s+[\'\"]{1}(.*)[\"\']{1}\%\}""")
    #block pattern
    block_pattern = re.compile(r"\{\%\s?block\s+([_a-z0-9A-Z]{1,})\s?\%\}")
    #extend, block replace pattern
    replace_pattern = (re.compile(r'\{\%\s?block\s+.*?\s?\%\}'), 
            re.compile(r'\{\%\s?endblock\s?\%\}'),
            re.compile(r'\{\%\s?extends\s+.*?\s?\%\}')
            )
    #include pattern
    include_pattern = re.compile(r'^include\(\"(.*)\"\)$')
    
    def __init__(self, path, basedir, debug=True):
        self.path = path
        self.basename = os.path.splitext(os.path.basename(path))[0]
        self.dirname = os.path.dirname(path)
        #path store path_html.py
        self.pypath = os.path.splitext(path)[0] + "_html.py"
        self.extends = []
        #templates base dir
        self.basedir = basedir
        self.debug = debug
    #argument path is the path of template file
    def getTemplate(self,path):
        f = file(path)
        template = f.read()
        f.close()
        return template
    #handle extends
    def handle_extends(self, tpl, extends_ptr=None):
        self.extends.insert(0, tpl)
        if not extends_ptr:
            extends_ptr = self.__class__.extend_pattern
        match_obj = re.match(extends_ptr,tpl)
        if match_obj:
            self.handle_extends( self.getTemplate(self.basedir+match_obj.group(1)), extends_ptr)
    #handle block
    def handle_blocks(self):
        if not self.extends:
            return ''
        else:
            origin = self.extends[0]
            if len(self.extends) > 1:
                block_ptr = self.__class__.block_pattern
                blocks = re.findall(block_ptr, origin)
                b_pts = [re.compile(r"""\{\%\s?block\s+"""+b+"""\s?\%\}(.*?)\{\%\s?endblock\s?\%\}""", re.S) for b in blocks]

                if blocks:
                    sons = self.extends[1:]
                    for son in sons:
                        #replace origin block
                        for i,b in enumerate(blocks):
                            sm = re.search(b_pts[i], son)
                            if sm:
                                origin = re.sub(b_pts[i], sm.group(), origin)
                        #find new block in son
                        sub_blocks = re.findall(block_ptr, son)
                        b_pts.extend([re.compile(r"""\{\%\s?block\s+"""+b+"""\s?\%\}(.*?)\{\%\s?endblock\s?\%\}""", re.S) \
                                for b in sub_blocks])
            #del extends and block, endblock tags
            origin = re.sub(self.__class__.replace_pattern[0], '', origin)
            origin = re.sub(self.__class__.replace_pattern[1], '', origin)
            origin = re.sub(self.__class__.replace_pattern[2], '', origin)
            return origin
    #return the codes of template
    def getCode(self,template):
        codes = [(False,"",0)]#(is_tag,code,level)
        
        _all = self.__class__.delimiter.split(template)
        tag = self.__class__.delimiter.findall(template)
        for i in _all:
            if i in tag:
                line_tag_flag , tcode = self.lineTag(i)
                if not line_tag_flag:
                    codes = codes + tcode
                else:
                    codes.append((line_tag_flag,tcode,self.setLevel(i,codes)))
            else:
                codes.append((False,self.getValue(i),self.setLevel(i,codes)))
        return codes
    #for special tag
    def lineTag(self,code):
        match_obj = re.match(self.__class__.include_pattern,code)
        return (False,self.getCode(self.getTemplate(self.basedir+match_obj.group(1)))) if match_obj else (True, code)
    #get ${ value }
    def getValue(self,code):
        values = []
        re_val = self.__class__.echo_pattern_jinja2
        
        vals = re_val.split(code)
        if len(vals) <= 1:
            return code

        for val in vals:
            v = re.match(self.__class__.echo_val_pattern_jinja2, val)
            if v is not None:
                values.append((True,v.group(1)))
            else:
                values.append((False,val))
        
        return values

    #set code's level
    def setLevel(self,co,codes):
        #further is end_tag
        for end in self.__class__.__END_TAG__:
            if re.match(end,co):
                self.is_end = True
                return codes[-1][2]-1
        #step 1
        for tag in self.__class__.__ELIF_ELSE__:#for elif else tag
            if re.match(tag,co):
                return codes[-1][2]-1
        #step 2, your have to finish step 1 then do step 2  
        for tag in self.__class__.__TAG__:
            if re.match(tag,co) and codes[-1][0]:#match,further is tag
                self.is_end = False 
                return codes[-1][2]+1
        #no match,but further is tag
        if codes[-1][0] and (not self.is_end):
            self.is_end = False 
            return codes[-1][2]+1
        #no match,match ,further is not tag
        self.is_end = False 
        return codes[-1][2]

    #write to file
    def write_file(self):###
        """use to create a *_html.py file"""
        f = open(self.pypath,'wb')
        f.writelines("#coding=utf-8\n")
        f.writelines("class Temp:\n")
        f.writelines("""\tdef __init__(self,ns):\n\t\tfor k in ns.keys():\n\t\t\tglobals()[k] = ns[k]\n\t\tself.html = []\n\n""")
        #out put code
        cnt = "\n"
        for _tag,_val,_level in self.codes:
            if _tag:
                if _val not in self.__class__.__end_tag__:
                    cnt = cnt + "\t\t" + "\t"*_level + _val + ":\n"
            else:
                if type(_val) is str or type(_val) is unicode:
                    cnt = cnt + "\t\t" + "\t"*_level + "self.html.append( u\"\"\"" + _val.replace('"','\\"') + "\"\"\")\n"
                else:
                    for _flag,_value in _val:
                        if _flag:
                            cnt = cnt + "\t\t" + "\t"*_level + "self.html.append( unicode(" + _value + "))\n"
                        else:
                            cnt = cnt + "\t\t" + "\t"*_level + "self.html.append( u\"\"\"" + _value.replace('"','\\"') + "\"\"\")\n"
        f.writelines(cnt)
                
        call = """\tdef __call__(self):\n\t\treturn self.html"""
        f.writelines(call)
        f.close()
    #use the namespace to execute *_html.py modules
    def render(self, **kw):
        py_mtime,tpl_mtime = None,None
        
        if not os.path.exists(self.path):#如果不存在tpl.html文件；引起文件不存在错误
            raise IOError,'tpl file is not exist'
        else:
            tpl_mtime = os.stat( self.path).st_mtime
        
        mod_name = self.dirname.replace('/','.')+'.'+self.basename+"_html"
        #如果不存在tpl_html.py文件；生成tpl_html.py文件; 或者debug模式，存在文件，也重新生成
        if not os.path.exists(self.pypath) or self.debug:
            self.handle_extends(self.getTemplate( self.path))#
            self.codes = self.getCode(self.handle_blocks())
            self.write_file()      
            sys.modules.pop(mod_name, None)

        __import__(mod_name)#加载
        mod = sys.modules[mod_name]
        ins = mod.Temp(kw)#new a class instance
        return ins()#__call__

    __call__ = render
###########################################################################
#####简单模板函数，可以加到过滤器中，this code from web.py
def htmlquote(text):
    """ >>> htmlquote("<'&\\">")
        '&lt;&#39;&amp;&quot;&gt;'
    """
    text = text.replace("&", "&amp;") # Must be done first!
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("'", "&#39;")
    text = text.replace('"', "&quot;")
    return text
def htmlunquote(text):
    """ >>> htmlunquote('&lt;&#39;&amp;&quot;&gt;')
        '<\\'&">'
    """
    text = text.replace("&quot;", '"')
    text = text.replace("&#39;", "'")
    text = text.replace("&gt;", ">")
    text = text.replace("&lt;", "<")
    text = text.replace("&amp;", "&") # Must be done last!
    return text
def websafe(val):
    """ >>> websafe("<'&\\">")
        '&lt;&#39;&amp;&quot;&gt;'
        >>> websafe(None)
        ''
        >>> websafe(u'\u203d')
        '\\xe2\\x80\\xbd'
    """
    if val is None:
        return ''
    if isinstance(val, unicode):
        val = val.encode('utf-8')

    val = str(val)
    return htmlquote(val)
#######################################################################
########静态文件服务器，可以在开发的时候用下，正式部署请换成nginx神马的
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
BLOCK_SIZE = 4096
class FileServerMiddleware(object):
    def __init__(self, application,path):
        self.path = path
        self.application = application
        
    def __call__(self, environ, start_response):
        path_info = environ["PATH_INFO"]
        if not path_info:
            return self.application(environ, start_response)
        root, ext = os.path.splitext(path_info.lower())
        if not ext:
            return self.application(environ, start_response)
        file_path = self.path + path_info
        #if exist this file and is a file
        if not os.path.isfile(file_path):
            raise Exception, "Can't find this file: " + file_path
        #if is allowed mime type file
        mimetype = ext_to_mimetype.get(ext, None)
        if mimetype is None:
            return self._forbidden(start_response)
        size = os.path.getsize(file_path)
        headers = [("Content-Type", mimetype)]
        #if is js or css file, gzip it
        if not self.isJsCssFile(environ['PATH_INFO']):
            headers.append(("Content-length", str(size)))
            start_response("200 OK", headers)
            return self._send_file( file_path)
        headers.append(('Content-Encoding','gzip'))
        start_response("200 OK", headers)
        return self._send_gzip_file( file_path)
    #send bin file
    def _send_file(self, file_path):
        with open(file_path,'rb') as f:
            block = f.read(BLOCK_SIZE)
            while block:
                yield block 
                block = f.read(BLOCK_SIZE)
    #send gzip file
    def _send_gzip_file(self, file_path):
        buffer = StringIO()
        output = gzip.GzipFile(mode='wb',compresslevel=9,fileobj=buffer)
        with open(file_path,'rb') as f:
            block = f.read(BLOCK_SIZE)
            while block:
                output.write(block)
                block = f.read(BLOCK_SIZE)
        output.close()
        buffer.seek(0)
        result = buffer.getvalue()
        buffer.close()
        return [result]

    def isJsCssFile(self,path):
        if path[-3:] == '.js' or path[-4:] == '.css':
            return True
    def _not_found(self, start_response):
        start_response("404 NOT FOUND", [("Content-type", "text/plain")])
        return ["Not found",]
    def _forbidden(self, start_response):
        start_response("403 FORBIDDEN", [("Content-type", "text/plain")])
        return ["Forbidden",]
###########################################################################
########很挫的错误显示中间件，由于模板系统没有trace功能，这个其实是个废物，也是抄来的
class HttpError(object):
    def __init__(self, msg='', err=None):
        self.msg, self.err = msg, err
class Redirect(HttpError):
    def __init__(self, status, location):
        self.status = status
        self.location = location
        super(HttpError, self).__init__()
def redirect(location, code=302):
    assert code in (201, 301, 302, 303, 305, 307), 'invalid code'
    if code == 301:
        code = '301 Moved Permanently'
    elif code == 302:
        code = '302 Found'
    return Redirect(code, location)
class ExceptionMiddleware(object):
    """The middleware we use."""
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        """Call the application can catch exceptions."""
        appiter = self.app(environ, start_response)
        if type(appiter) is HttpError:
            traceback = ['Traceback (most recent call last):']
            traceback.append(appiter.msg)
            if appiter.err:
                e_type, e_value, tb = appiter.err
                traceback += format_tb(tb)
                traceback.append('%s: %s' % (e_type, e_value))
            start_response("500 Internal Server Error", [("Content-type", "text/plain")])
            return traceback#u'\n'.join(traceback)#.encode('utf8')
        return ''.join(appiter)

###########################################################################
########框架核心用到的一些函数和对象，不解释
#url_arg_parse#--------------------------------------------------------
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
#clear func_globals
def clear_g(gl, cl):
    for key in cl.keys():
        gl.pop(key, None)
#filter class for ror |
class Filter(object):
    def __init__(self, func):
        self.func = func
    def __ror__(self, val):
        return self(val)
    def __call__(self, val):
        return self.func(val)
#request Global object
class G(object):
    def __getattr__(self, attr):
        return None
#cached_property, user's function
class cached_property(object):
    def __init__(self, func):
        self.func = func
    def __get__(self, obj, cls):
        if obj is None: return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value
cached_attr = cached_property
###########################################################################
########query_str，session，request，三个对象每次请求都是重建的，不存在线程安全问题
class QueryString(object):
    mshort = re.compile("[A-Z0-9a-z_]{1,}=[^=&]{1,}")
    mlong = re.compile("([A-Z0-9a-z_]{1,}=[^=&]{1,})&([A-Z0-9a-z_]{1,}=[^=&]{1,}&){0,}[A-Z0-9a-z_]{1,}=[^=&]{1,}")
    def __init__(self,qstr):
        self.qstr = qstr
        self.data = {}
        if self.isQstr(qstr):
            self.sliceEqualSign()

    def sliceEqualSign(self):
        strs = self.qstr.split('&')
        for item in strs:
            k,v = item.split('=')
            if self.data.has_key(k):
                if not type(self.data[k]) is list:
                    self.data[k] = [self.data[k]]
                self.data[k].append(v)
            else:
                self.data[k] = v
        
    def getData(self):
        return self.data
    def __getitem__(self,key):
        return self.data[key]
    def get(self, *args):
        if len(args) == 3:
            return args[2]( self.data.get(args[0], args[1]))
        return self.data.get(*args)
    def get_list(self, *args):
        op = None
        if len(args) == 3:
            op = args[2]
        if not self.data.has_key(args[0]):
            if len(args) >= 2:
                return args[1]
            else:
                raise Exception("Can't found value of %s!" % args[0])
        val = self.data.get(args[0])
        return [op(i) for i in val] if op else val
    
    def isQstr(self,qstr):
        #match a=arg1
        mshort = re.match(self.__class__.mshort, qstr)
        #match a=arg1&(b=arg2&)c=arg3
        mlong = re.match(self.__class__.mlong, qstr)
        return False if not mshort and not mlong else True

#session#--------------------------------------------------------
class Session(dict):
    def __init__(self, rs=None, cookie=None, expires=1800*4):#two hours
        self.rs = rs
        self.cookie = cookie
        self.expires = expires
        
        if self.cookie.has_key('__soxo_session_id'):
            self.sessionID = self.cookie["__soxo_session_id"].value
        else:
            self.sessionID = str(uuid4())
        try:
            data = self.rs.get(self.sessionID)
            self.data = pickle.loads(data) if data else {}
        except:
            self.data = {}
            
    def set_expires(self, expires=None):
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
        self.cookie["__soxo_session_id"]['expires'] = self.expires

#request obj#--------------------------------------------------------
class Request(object):
    def __init__(self,environ, server_name):
        self.method = environ.get("REQUEST_METHOD","")
        #self.form = cgi.FieldStorage(environ["wsgi.input"] if environ.has_key('wsgi.input') else None, environ=environ,keep_blank_values=1)
        self.form, self.files = parse_form_data(environ)

        path = environ.get('PATH_INFO', '')
        self.path = path if path.endswith('/') else path + '/'
        self.server_name = environ.get('SERVER_NAME', '')
        self.subdomain = environ.get('SERVER_NAME', '').replace(server_name, '')
        
        self.is_ajax = self.is_xhr = environ.get('HTTP_X_REQUESTED_WITH','').lower() == 'xmlhttprequest'
        self.is_post, self.is_get = self.method == 'POST', self.method == 'GET'
                
        self.status = "200 0k"
        self.headers = []
        self.env = self.environ = environ
        
    def set_req(self, session, cookie, qstr):
        self.session = session
        self.cookie = cookie
        self.args = self.query_str = qstr
        
    def save2file(self,name,path):
        with file(path,'wb') as f:
            f.write(self.files.get(name).read())
        return True
###########################################################################
########框架核心对象，可以模块化开发，只能2级
#base view#--------------------------------------------------------
class BaseView(object):
    def __init__(self, req_info):
        self.req_info = req_info
    def __call__(self,**args):
        callback = getattr(self, self.req_info['request'].method.lower())
        callback.func_globals.update(self.req_info)
        callback.func_globals['req_info'] = self.req_info
        return callback(**args)
#app and module#--------------------------------------------------------
class Module(object):
    def __init__(self, name=__name__):
        self.name = name
        self.subdomain = ''
        self.url_rules = []
        self.module = self.name
        self.handlers = {}
        
    def add_url_rule(self, rule, f, methods):
        pattern, args, modfunc_url = url_arg_parse(rule)
        self.url_rules.append((pattern, \
                {'methods':methods, 'args':args, 'reverse_route':modfunc_url, 'callback':f, \
                'module':self.module+'.'+f.__name__
                }))
    
    def route(self, rule, methods=('GET',)):
        def decorator(f):
            self.add_url_rule(rule, f, methods)
            if not hasattr(f, '__spec'):#@
                setattr(f, '__spec', inspect.getargspec(f))
            return f
        return decorator
    
    def invoke_handler(self, key, handlers, req_info):
        resp = None
        if self.handlers.has_key(key):
            self.handlers[key].func_globals.update(req_info)
            resp = self.handlers[key]()
            clear_g(self.handlers[key].func_globals, req_info)
        elif handlers and handlers.has_key(key):
            handlers[key].func_globals.update(req_info)
            resp = handlers[key]()
            clear_g(handlers[key].func_globals, req_info)
        return resp
    
    def arg_type_convert(self, args, types):#except URLErr
        for k in args.keys():
            if types[k] == 'int':
                args[k] = int(args[k])
            elif types[k] == 'float':
                args[k] = float(args[k])
        return args
        
    def url_dispatch(self, path, req_info, handlers={}):
        #@#new 最少args的优先, /login/ first than /<opt>/
        match_rules, rule = filter(lambda x: re.search(x[0], path), self.url_rules[::-1]), None
        if not match_rules:
            resp = self.invoke_handler('error404_handler', handlers, req_info)
            if not resp:
                return HttpError("404 Error----Url can't match any handler. Url can't route!")
            return resp
        elif len(match_rules) == 1:
            rule = match_rules[0]
        else:
            arg_counts = [len( m[1]['args']) for m in match_rules]
            rule = match_rules[arg_counts.index(min(arg_counts))]
        cb_dict = rule[1]
        match = re.search(rule[0], path)
        #test methods allow
        if req_info['request'].method not in cb_dict['methods']:
            return HttpError(req_info['request'].method + ' not allow!')
        #get url args
        args = match.groupdict()
        self.arg_type_convert(args, cb_dict['args'])
        #if has before_handler
        self.invoke_handler('before_handler', handlers, req_info)
        #class view enable
        callback = cb_dict['callback']
        if type(callback) is not fn_type:
            callback = callback(req_info)
        else:
            callback.func_globals.update(req_info)
            callback.func_globals['req_info'] = req_info
        #response
        try:
            resp = callback(**args)
            if type(callback) is fn_type:
                clear_g(callback.func_globals, req_info)
        except Exception as e:##use httperr, err=500, err=401...
            if type(callback) is fn_type:#class rebuild instance, not need to clear_g
                clear_g(callback.func_globals, req_info)
            ##new http exceptions
            if e.message and type(e.message) is int and e.message != 500:
                resp = self.invoke_handler('error%d_handler' % e.message, handlers, req_info)
            else:
                resp = self.invoke_handler('error500_handler', handlers, req_info)
            if not resp:
                print 'error in occur in', callback.__name__,'-------------------'
                return HttpError(err=exc_info())
        #if has after_handler
        self.invoke_handler('after_handler', handlers, req_info)
        return resp

    def before_request(self):
        """请求前装饰器"""
        def decorator(f):
            self.handlers['before_handler'] = f
            return f
        return decorator
    def after_request(self):
        """请求后装饰器"""
        def decorator(f):
            self.handlers['after_handler'] = f
            return f
        return decorator
    def error_404(self):
        """404错误处理器"""
        def decorator(f):
            self.handlers['error404_handler'] = f
            return f
        return decorator
    def error_500(self):
        """500错误处理器"""
        def decorator(f):
            self.handlers['error500_handler'] = f
            return f
        return decorator
    def error_401(self):
        """401错误处理器"""
        def decorator(f):
            self.handlers['error401_handler'] = f
            return f
        return decorator

class Soxo(Module):
    
    def __init__(self, name=__name__, server_name=''):
        self.name = name
        self.url_prefix = ''
        self.server_name = server_name.replace('www','') if server_name.startswith('www.') else '.'+server_name
        
        self.url_rules = []
        self.module = ''
        self.modules = []
        self.handlers = {}

        self.static = '/home/sx/soft/fw/trip/static'
        self.debug = False
        self.templates = 'templates/'
        
        self.cookie_expires = 24*30*60  #one day
        self.session_expires = 1800#30*60, if cookie_expires < session_expires, s_e = c_e
        self.csrf_session_key = ''
        self.csrf_enabled = True
        # redis.Redis(host='localhost', port=6379, db=0), **{host:, port:, db:}
        self.redis = None
        
        def url_for(modfunc, **args):
            url_rules = []
            mod, func = modfunc.split('.')
            prefix_url = ''
            for prefix, module in self.modules:
                if module.name == mod:
                    url_rules = module.url_rules
                    prefix_url = prefix
                    break
            else:
                url_rules = self.url_rules
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
                    rule = match_rules[arg_counts.index(max(arg_counts))]
                else:
                    rule = rules[0]
            #print rule, args, '\n----------\n', match_rules
            qs, reverse = {}, rule[1]['reverse_route']
            for k in args.keys():
                args[k] = str(args[k])
                if k not in rule[1]['args']:
                    qs[k] = args[k]
                    del args[k]
            try:
                url = prefix_url if mod else ''
                return url + reverse % args + '?' + urlencode(qs) if qs else url + reverse % args
            except:
                return HttpError('%s\'s arguments err------past args are %s: \n accept args are %s' % (modfunc, str(args), str(rule[1]['args'])))
            
        self.filters = {}
        self.init_filters()
        self.__tools__ = {'url_for':url_for}
                
        def render( tpl="", tpl_dir=self.templates, **kw):
            kw.update(self.__tools__)
            #给模板注入过滤器
            kw.update(self.filters)
            kw.update(req_info)
            try:
                return Template(tpl_dir + tpl, tpl_dir, req_info['debug'])(**kw)
            except Exception as e:
                print ('template occur error------------')
                return HttpError('tpl err: %s' % str(e), exc_info())
        
        #给处理函数使用的
        self.__tools__.update({ 'render':render,'Template':Template,'redirect':redirect, \
                'quote':htmlquote,'unquote':htmlunquote,'safe':websafe})
        
    def register_filter(name):
        """注册一个过滤器"""
        def decorator(f):
            self.filters[name] = Filter(f)
            return self.filters[name]
        return decorator
    def init_filters(self):
        """建立基本过滤器"""
        self.filters['safe'] = Filter(websafe)
        self.filters['quote'] = Filter(htmlquote)
        self.filters['unquote'] = Filter(htmlunquote)
    def init_session(self):
        """建立session"""
        if self.redis:
            import redis
            self.rs = redis.Redis(**self.redis)
            
    def url_dispatch(self, path, req_info):
        #先匹配module，再匹配app自己
        empty_prefix, empty_prefix_module = None, None#path='/', prefix_url=''
        for prefix_url, module in self.modules:
            #subdomain match
            if module.subdomain and req_info['request'].subdomain == module.subdomain:
                #subdomain support multi module
                if path.startswith(prefix_url):
                    return module.url_dispatch(path.replace(prefix_url, '', 1), req_info, handlers=self.handlers)
            elif not prefix_url:
                empty_prefix, empty_prefix_module = prefix_url, module
                continue
            #prefix_url match
            elif path.startswith(prefix_url):
                return module.url_dispatch(path.replace(prefix_url, '', 1), req_info, handlers=self.handlers)
        else:
            if empty_prefix_module:
                return empty_prefix_module.url_dispatch(path, req_info, handlers=self.handlers)

            return super(Soxo, self).url_dispatch(path, req_info)
        
    def __call__(self, environ, start_response):
        """wsgi wrapper"""
        #init request
        req_info = {'g': G()}
        req_info['debug'] = self.debug
        #cookie and session and query_str
        req_info['cookie'] = SimpleCookie(environ.get("HTTP_COOKIE",""))
        req_info['query_str'] = QueryString(environ["QUERY_STRING"])
        if self.redis:
            req_info['session'] = Session(rs=self.rs, cookie=req_info['cookie'], expires=self.session_expires)
        #handle request
        req_info['request'] = Request(environ, self.server_name)
        request = req_info['request']
        request.csrf_session_key, request.csrf_enabled = self.csrf_session_key, self.csrf_enabled
        request.set_req(req_info.get('session',None), req_info['cookie'], req_info['query_str'])
        #handle dispatch
        self.__tools__['render'].func_globals['req_info'] = req_info
        req_info.update(self.__tools__)
        resp =  self.url_dispatch(req_info['request'].path, req_info)
        #cookie handle
        req = req_info['request']
        if (len(req_info['cookie'])!=0):
            for k, v in req_info['cookie'].items():
                if '__utm' not in str(v):
                    if not v['path']:#set cookie is useful for all request
                        v['path'] = '/'
                    if not v['expires']:
                        v['expires'] = self.cookie_expires
                req.headers.append( ('Set-Cookie', str(v).split(': ')[1]) )
        #handle redirect
        if type(resp) is Redirect:
            req.status = resp.status
            req.headers.append(('Location', resp.location))
            resp = ''
        elif type(resp) is HttpError:
            return resp
        #start resp
        start_response(req.status, req.headers)
        if type(resp) is str:
            return resp
        elif type(resp) is unicode:
            return resp.encode('utf8')
        return ''.join([r.encode('utf8') for r in resp])

    def register_module(self, prefix_url, module, subdomain=''):
        module.subdomain = subdomain
        self.modules.append((prefix_url, module))
    def run(self, host='localhost', port=9000):
        from wsgiref.simple_server import make_server
        #debug mode can serve static file and check trace
        app = self
        app.init_session()
        if self.debug:
            app = FileServerMiddleware(app, self.static)
            app = ExceptionMiddleware(app)
        srv = make_server(host, port, app)
        srv.serve_forever()
        
    def run_cherrypy_server(self, host='localhost', port=9000):
        from wsgiserver import CherryPyWSGIServer
        #debug mode can serve static file and check trace
        app = self
        app.init_session()
        if self.debug:
            app = FileServerMiddleware(app, self.static)
            app = ExceptionMiddleware(app)
        server = CherryPyWSGIServer( (host, port), app)#, server_name='www.cherrypy.example')
        server.start()
        
    def run_gevent_server(self, host='localhost', port=9000):
        from gevent.pywsgi import WSGIServer
        #debug mode can serve static file and check trace
        app = self
        app.init_session()
        if self.debug:
            app = FileServerMiddleware(app, self.static)
            app = ExceptionMiddleware(app)
        WSGIServer((host, port), app).serve_forever()

def run_devserver():
        """just for dev"""
        from subprocess import Popen as popen
        import time

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

