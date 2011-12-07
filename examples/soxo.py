#coding=utf-8
"""a micro flask like python web framework, see README for more infomation"""

__all__ = ['Template', 'Module', 'Soxo', 'BaseView']

import re, os, sys, pickle, os.path

from datetime import datetime
from copy import deepcopy
from urllib import urlencode

from sys import exc_info
from traceback import format_tb

from hashlib import md5
from Cookie import SimpleCookie
from types import FunctionType as fn_type

#########################################################################
######简单模板系统代码------支持filter，extends，include， 和一些复杂表达式
#########################################################################
#tag have endtag
__TAG__ = (
    '\s?if',#0-n white space + if
    '\s?for',
    )
#end tag
__END_TAG__ = (
    '\s?endif',
    '\s?endfor',
    )
__end_tag__ = (
    'endif',
    'endfor',
    )
#elif,else
__elif_else__ = (
    '\s?elif',
    '\s?else',
    )

class Template(object):

    delimiter = re.compile(r"\{\%\s?(.*?)\s?\%\}")
    
    def __init__(self,path):
        self.path = path
        self.basename = os.path.splitext(os.path.basename(path))[0]
        self.dirname = os.path.dirname(path)
        #path store path_html.py
        self.pypath = os.path.splitext(path)[0] + "_html.py"
        self.extends = []
        
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
            extends_ptr = re.compile(r"""\{\%\s?extends\s+[\'\"]{1}(.*)[\"\']{1}\%\}""")
        match_obj = re.match(extends_ptr,tpl)
        if match_obj:
            self.handle_extends( self.getTemplate(self.dirname+'/'+match_obj.group(1)), extends_ptr)
            
    #handle block
    def handle_blocks(self):
        if not self.extends:
            return ''
        else:
            origin = self.extends[0]
            if len(self.extends) > 1:
                block_ptr = re.compile(r"""\{\%\s?block\s+([_a-z0-9A-Z]{1,})\s?\%\}""")
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
            origin = re.sub(r'\{\%\s?block\s+.*?\s?\%\}', '', origin)
            origin = re.sub(r'\{\%\s?endblock\s?\%\}', '', origin)
            origin = re.sub(r'\{\%\s?extends\s+.*?\s?\%\}', '', origin)
            return origin

    #return the codes of template
    def getCode(self,template):
        codes = [(False,"",0)]#(is_tag,code,level)

        all = self.delimiter.split(template)
        tag = self.delimiter.findall(template)

        for i in all:
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
        match_obj = re.match(r'^include\(\"(.*)\"\)$',code)
        if match_obj:#not none
            return False,self.getCode(self.getTemplate(self.dirname+'/'+match_obj.group(1)))
        else:
            return True,code

    #get ${ value }
    def getValue(self,code):
        values = []
        re_val = re.compile(r"(\$\{.*?\})")
        
        vals = re_val.split(code)
        if len(vals) <= 1:
            return code

        for val in vals:
            v = re.match(r"""\$\{\s?(.*?)\s?\}""",val)
            if v is not None:
                values.append((True,v.group(1)))
            else:
                values.append((False,val))

        return values

    #set code's level
    def setLevel(self,co,codes):
        #further is end_tag
        for end in __END_TAG__:
            if re.match(end,co):
                self.is_end = True
                return codes[-1][2]-1
        #step 1
        for tag in __elif_else__:#for elif else tag
            if re.match(tag,co):
                return codes[-1][2]-1
        #step 2, your have to finish step 1 then do step 2  
        for tag in __TAG__:
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
        f = open(self.pypath,'w')

        f.writelines("#coding=utf-8\n")
        f.writelines("class Temp:\n")
        init = """\tdef __init__(self,ns):
\t\tfor k in ns.keys():
\t\t\tglobals()[k] = ns[k]
\t\tself.html = []\n
"""
        f.writelines(init)
        #out put code
        cnt = "\n"
        for _tag,_val,_level in self.codes:
            if _tag:
                if _val not in __end_tag__:
                    cnt = cnt + "\t\t" + "\t"*_level + _val + ":\n"
            else:
                if type(_val) is str:
                    cnt = cnt + "\t\t" + "\t"*_level + "self.html.append( \"\"\"" + _val + "\"\"\")\n"
                else:
                    for _flag,_value in _val:
                        if _flag:
                            cnt = cnt + "\t\t" + "\t"*_level + "self.html.append( str(" + _value + "))\n"
                        else:
                            cnt = cnt + "\t\t" + "\t"*_level + "self.html.append( \"\"\"" + _value + "\"\"\")\n"
        f.writelines(cnt)
                
        call = """\tdef __call__(self):
\t\treturn self.html"""
        f.writelines(call)
        f.close()

    #use the namespace to execute *_html.py modules
    def render(self, **kw):
        py_mtime,tpl_mtime = None,None
        
        if not os.path.exists(self.path):#如果不存在tpl.html文件；引起文件不存在错误
            raise IOError,'tpl file is not exist'
        else:
            tpl_mtime = os.stat( self.path).st_mtime
            
        if not os.path.exists(self.pypath):#如果不存在tpl_html.py文件；生成tpl_html.py文件
            #self.codes = self.getCode(self.getTemplate( self.path))
            self.handle_extends(self.getTemplate( self.path))#
            self.codes = self.getCode(self.handle_blocks())
            self.write_file()
        py_mtime = os.stat(self.pypath).st_mtime

        if sys.modules.has_key( self.basename+"_html"):#如果已经加载模块
            if tpl_mtime > py_mtime:#reload module，如果tpl文件已经重新修改过，重新生成tpl_html.py文件并加载
                self.handle_extends(self.getTemplate( self.path))#
                self.codes = self.getCode(self.handle_blocks())
                self.write_file()
            del sys.modules[self.basename+"_html"]
        elif tpl_mtime > py_mtime:#文件没加载且已经修改过tpl；生成tpl_html.py文件
            self.handle_extends(self.getTemplate( self.path))#
            self.codes = self.getCode(self.handle_blocks())
            self.write_file()

        mod_name = self.dirname.replace('/','.')+'.'+self.basename+"_html"
        __import__(mod_name)#加载
        #######
        mod = sys.modules[mod_name]
        ins = mod.Temp(kw)#new a class instance
        return ins()#__call__

    __call__ = render
###########################################################################
#####简单模板函数，可以加到过滤器中，this code from web.py
###########################################################################
def htmlquote(text):
    """
    Encodes `text` for raw use in HTML.
    
        >>> htmlquote("<'&\\">")
        '&lt;&#39;&amp;&quot;&gt;'
    """
    text = text.replace("&", "&amp;") # Must be done first!
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("'", "&#39;")
    text = text.replace('"', "&quot;")
    return text

def htmlunquote(text):
    """
    Decodes `text` that's HTML quoted.


        >>> htmlunquote('&lt;&#39;&amp;&quot;&gt;')
        '<\\'&">'
    """
    text = text.replace("&quot;", '"')
    text = text.replace("&#39;", "'")
    text = text.replace("&gt;", ">")
    text = text.replace("&lt;", "<")
    text = text.replace("&amp;", "&") # Must be done last!
    return text
def websafe(val):
    """
    Converts `val` so that it's safe for use in UTF-8 HTML.
    
        >>> websafe("<'&\\">")

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
#######################################################################
ext_to_mimetype = {
    '.html': 'text/html',
    ".htm": "text/html",
    
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    ".gif": "image/gif",
    
    ".uu":  "application/octet-stream",
    ".exe": "application/octet-stream",
    ".ps":  "application/postscript",
    ".zip": "application/zip",
    ".sh":  "application/x-shar",
    ".tar": "application/x-tar",
    '.pdf': 'application/pdf',
    ".snd": "audio/basic",
    ".au": "audio/basic",
    ".wav": "audio/x-wav",
    
    '.css': 'text/css',
    '.txt': 'text/plain',
    ".c": "text/plain",
    ".cc": "text/plain",
    ".cpp": "text/plain",
    ".h": "text/plain",
    ".pl": "text/plain",
    ".java": "text/plain",
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
        if path_info == '/favicon.ico':
            file_path = self.path + path_info
        else:
            file_path = self.path + path_info.split('/static')[1]
        if not os.path.isfile(file_path):
            raise Exception, "Can't find this file: " + file_path
        
        mimetype = ext_to_mimetype.get(ext, None)
        if mimetype is None:
            return self._forbidden(start_response)
        size = os.path.getsize(file_path)
        headers = [("Content-Type", mimetype)]

        if not self.isJsCssFile(environ['PATH_INFO']):
            headers.append(("Content-length", str(size)))
            start_response("200 OK", headers)
            return self._send_file( file_path)
        
        start_response("200 OK", headers)
        headers.append(('Content-Encoding','gzip'))
        return self._send_gzip_file( file_path)
    
    def _send_file(self, file_path):
        with open(file_path,'rb') as f:
            block = f.read(BLOCK_SIZE)
            while block:
                yield block 
                block = f.read(BLOCK_SIZE)
        
    def _send_gzip_file(self, file_path):
        buffer = StringIO.StringIO()
        output = gzip.GzipFile(
            mode='wb',
            compresslevel=9,
            fileobj=buffer
        )
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
###########################################################################
class ExceptionMiddleware(object):
    """The middleware we use."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        """Call the application can catch exceptions."""
        appiter = None
        try:
            appiter = self.app(environ, start_response)
            for item in appiter:
                yield item
        except:
            e_type, e_value, tb = exc_info()
            traceback = ['Traceback (most recent call last):']
            traceback += format_tb(tb)
            traceback.append('%s: %s' % (e_type.__name__, e_value))
            try:
                start_response('500 INTERNAL SERVER ERROR', [
                               ('Content-Type', 'text/plain')])
            except:
                pass
            yield '\n'.join(traceback)

        if hasattr(appiter, 'close'):
            appiter.close()
###########################################################################
########框架核心用到的一些函数和对象，不解释
###########################################################################
#url_arg_parse#--------------------------------------------------------
def url_arg_parse(origin):
    args = [argstr.lstrip('<').rstrip('>').split(':') for argstr in re.findall('<[^<>]*>', origin)]
    url = re.split('<[^<>]+>', origin)
    modfunc_url = deepcopy(url)###
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
#rediretion
class Redirect(object):
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
###########################################################################
########query_str，session，request，三个对象每次请求都是重建的，不存在线程安全问题
###########################################################################
class QueryString:
    def __init__(self,qstr):
        self.qstr = qstr
        self.data = {}
        self.mshort = re.compile("[A-Z0-9a-z_]{1,}=[^=&]{1,}") 
        self.mlong = re.compile("([A-Z0-9a-z_]{1,}=[^=&]{1,})&([A-Z0-9a-z_]{1,}=[^=&]{1,}&){0,}[A-Z0-9a-z_]{1,}=[^=&]{1,}")
        
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
        if op:
            return [op(i) for i in val]
        return val
    
    def isQstr(self,qstr):
        #match a=arg1
        mshort = re.match(self.mshort, qstr)
        #match a=arg1&(b=arg2&)c=arg3
        mlong = re.match(self.mlong, qstr)

        if not mshort and not mlong:
            return False
        return True

#session#--------------------------------------------------------
class Session(dict):
    def __init__(self, rs=None, mc=None, cookie=None, expires=1800):

        self.mc = mc
        self.rs = rs
        self.cookie = cookie
        self.expires = expires
        
        try:
            self.sessionID = self.cookie["__soxo_session_id"].value
        except:
            self.sessionID = md5(str(datetime.now())).hexdigest()
            
        try:
            if rc:
                self.data = self.rs.get(self.sessionID)
            elif mc:
                self.data = pickle.loads( self.mc.get(self.sessionID) )
        except:
            self.data = {}
            
    def setExpires(self,expires):
        self.expires = expires
        
    def __getitem__(self,key):
        return self.data[key]
    
    def get(self, key, default=None):
        return self.data.get(key, default)
    
    def __setitem__(self,key,value):
        self.data[key] = value

    def id(self,key):
        self.sessionID
    
    def __delitem__(self,key):
        del self.data[key]
        
    def save(self):
        if self.rs:
            self.rs.set(self.sessionID, self.data)
            self.rs.expire(self.expires)
        elif self.mc:
            self.pickledata = pickle.dumps(self.data)
            self.mc.set(self.sessionID, self.pickledata, time=self.expires)
        self.cookie["__soxo_session_id"] = self.sessionID
        self.cookie["__soxo_session_id"]['expires'] = self.expires

#request obj#--------------------------------------------------------
class Request:

    def __init__(self,environ):
        self.method = environ.get("REQUEST_METHOD","")
        if self.method == "POST":
            try:
                self.form = cgi.FieldStorage(environ["wsgi.input"],
                        environ=environ,keep_blank_values=1)
            except Exception as e:
                print ("init form error!...", e)
                
        path = environ.get('PATH_INFO', '')
        self.path = path if path.endswith('/') else path + '/'
                
        self.status = "200 0k"
        self.headers = []
        self.env = environ
        
    def save2file(self,name,path=None):
        if (self.form[name].type).lower() in 'text/plain':
            return
        if not path:
            path = self.form[name].filename

        f = file(path,'wb')
        f.flush()
        f.write(self.form[name].value)
        f.close()
        
###########################################################################
########框架核心对象，可以模块化开发，只能2级
###########################################################################
#base view#--------------------------------------------------------
class BaseView(object):
    def __init__(self, req_info):
        self.req_info = req_info
        
    def __call__(self,**args):
        callback = getattr(self, self.req_info['request'].method.lower())
        callback.func_globals.update(self.req_info)
        return callback(**args)
#app and module#--------------------------------------------------------
class Module(object):

    def __init__(self, name=__name__, url_prefix=''):
        self.name = name
        self.url_prefix = url_prefix
        
        self.url_rules = []
        self.module = self.name
        
    def add_url_rule(self, rule, f, methods):
        pattern, args, modfunc_url = url_arg_parse(self.url_prefix + rule)
        self.url_rules.append((pattern, \
                {'methods':methods, 'args':args, 'reverse_route':modfunc_url, 'callback':f, \
                'module':self.module+'.'+f.__name__
                }))
    
    def route(self, rule, methods=('GET',)):
        def decorator(f):
            self.add_url_rule(rule, f, methods)
            return f
        return decorator

class Soxo(Module):
    
    def __init__(self, name=__name__):
        self.name = name
        self.url_prefix = ''
        
        self.url_rules = []
        self.module = ''
        
        #handler register
        self.before_handler, self.after_handler, self.error404_handler, self.error500_handler = None, None, None, None
        
        self.static = './static/'
        self.debug = False
        self.templates = 'templates/'
        
        self.cookie_expires = 24*30*60  #one day
        self.session_expires = 1800#30*60, if cookie_expires < session_expires, s_e = c_e
        
        # ['127.0.0.1:11211']
        self.memcache = None
        # redis.Redis(host='localhost', port=6379, db=0), **{host:, port:, db:}
        self.redis = None
        
        def url_for(modfunc, url_rules=self.url_rules, **args):
            for rule in url_rules:
                if modfunc == rule[1]['module']:
                    types = rule[1]['args']
                    reverse = rule[1]['reverse_route']

                    qs = {}
                    for k in args.keys():
                        args[k] = str(args[k])
                        if k not in types:
                            qs[k] = args[k]
                            del args[k]
                    try:
                        if qs:
                            return reverse % args + '?' + urlencode(qs)
                        return reverse % args
                    except:
                        raise Exception, modfunc + "'s arguments err!"
            raise Exception, "Can't reverse route of :"+modfunc
            
        self.filters = {}
        self.init_filters()
        
        self.__tools__ = {'url_for':url_for}
                
        def render( tpl="", tpl_dir=self.templates, **kw):
            kw.update(self.__tools__)
            #给模板注入过滤器
            kw.update(self.filters)
            return Template(tpl_dir + tpl)(**kw)
        
        #给处理函数使用的
        self.__tools__.update({'quote':htmlquote,'unquote':htmlunquote,'safe':websafe, \
                'render':render,'Template':Template,'redirect':redirect})
        
        self.init_session()
        
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
        """建立session，需要memcache或者redis"""
        #if redis or memcache addr is set, session enable, redis come first
        if self.redis:
            import redis
            self.rs = redis.Redis(**self.redis)
        elif self.memcache:
            import memcache
            self.mc = memcache.Client(self.memcache, debug=self.debug)
        
    def __call__(self, environ, start_response):
        """wsgi wrapper"""
        #init request
        req_info = {'g': G()}
        
        #cookie and session and query_str
        req_info['cookie'] = SimpleCookie(environ.get("HTTP_COOKIE",""))
        req_info['query_str'] = QueryString(environ["QUERY_STRING"])
        if self.redis:
            req_info['session'] = Session(rs=self.rs, cookie=req_info['cookie'], expires=self.session_expires)
        elif self.memcache:
            req_info['session'] = Session(mc=self.mc, cookie=req_info['cookie'], expires=self.session_expires)
        
        #handle request
        req_info['request'] = Request(environ)
        req_info.update(self.__tools__)
        
        #handle dispatch
        resp =  self.url_dispatch(req_info['request'].path, req_info)
        
        #session.save
        if self.redis or self.memcache:
            req_info['session'].save()
        
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
            
        #start resp
        start_response(req.status, req.headers)
        return resp
    
    def arg_type_convert(self, args, types):#except URLErr
        for k in args.keys():
            if types[k] == 'int':
                args[k] = int(args[k])
            elif types[k] == 'float':
                args[k] = float(args[k])
        return args
        
    def url_dispatch(self, path, req_info):
            for regex, cb_dict in self.url_rules:
                match = re.search(regex, path)
                #if path match a route url
                if match:
                    #test methods allow
                    if req_info['request'].method not in cb_dict['methods']:
                        raise Exception, req_info['request'].method + ' not allow!'
                    #get url args
                    args = match.groupdict()
                    self.arg_type_convert(args, cb_dict['args'])
                    #if has before_handler
                    if self.before_handler:
                        self.before_handler.func_globals.update(req_info)
                        self.before_handler()
                        clear_g(self.before_handler.func_globals, req_info)
                    #class view enable
                    callback = cb_dict['callback']
                    if type(callback) is not fn_type:
                        callback = callback(req_info)
                    else:
                        callback.func_globals.update(req_info)
                    #response
                    try:
                        resp = callback(**args)
                        if type(callback) is fn_type:
                            clear_g(callback.func_globals, req_info)
                    except Exception as e:
                        if type(callback) is fn_type:#class rebuild instance, not need to clear_g
                            clear_g(callback.func_globals, req_info)
                        #500error
                        if self.error500_handler:
                            if type(callback) is fn_type:
                                clear_g(callback.func_globals, req_info)
                            self.error500_handler.func_globals.update(req_info)
                            resp = self.error500_handler()
                            clear_g(self.error500_handler.func_globals, req_info)
                            return resp
                        raise e
                    #if has after_handler
                    if self.after_handler:
                        self.after_handler.func_globals.update(req_info)
                        self.after_handler()
                        clear_g(self.after_handler.func_globals, req_info)
                    return resp
            #404
            else:
                if self.error404_handler:
                    self.error404_handler.func_globals.update(req_info)
                    resp = self.error404_handler()
                    clear_g(self.error404_handler.func_globals, req_info)
                    return resp
                raise  Exception("404 Error----Url can't match any handler. Url can't route!")
    
    def register_module(self, module):
        self.url_rules.extend(module.url_rules)#not + 
            
    def run(self, host='localhost', port=9000):
        from wsgiref.simple_server import make_server
        #debug mode can serve static file and check trace
        app = self
        if self.debug:
            import gzip
            import StringIO
            app = FileServerMiddleware(app, self.static)
            app = ExceptionMiddleware(app)
            
        srv = make_server(host, port, app)
        srv.serve_forever()
        
    def run_cherrypy_server(self, host='localhost', port=9000):
        from wsgiserver import CherryPyWSGIServer
        #debug mode can serve static file and check trace
        app = self
        if self.debug:
            import gzip
            import StringIO
            app = FileServerMiddleware(app, self.static)
            app = ExceptionMiddleware(app)
        
        server = CherryPyWSGIServer( (host, port), app)#, server_name='www.cherrypy.example')
        server.start()
        
    def run_gevent_server(self, host='localhost', port=9000):
        pass
                
    def before_request(self):
        """请求前装饰器"""
        def decorator(f):
            self.before_handler = f
            return f
        return decorator
        
    def after_request(self):
        """请求后装饰器"""
        def decorator(f):
            self.after_handler = f
            return f
        return decorator
        
    def error_404(self):
        """404错误处理器"""
        def decorator(f):
            self.error404_handler = f
            return f
        return decorator
        
    def error_500(self):
        """500错误处理器"""
        def decorator(f):
            self.error500_handler = f
            return f
        return decorator

def run_devserver(entry="", host='localhost', port=9000):
        """just for dev"""
        from multiprocessing import Process
        import time, getopt
        #args option parse
        opts, args = getopt.getopt(sys.argv[1:], "e:p:h:")
        if not '-e' in [opt[0] for opt in opts]:
            print ("you must provide a entrypoint, like:\n\tpython soxo.py -e appmodule.appinstance -h 0.0.0.0 -p 9000")
            exit(0)
        for op, value in opts:
            if op == '-e':
                print value
                entry = value
            elif op == '-p':
                port = value
            elif op == '-h':
                host = value
        #get mod.app
        mod = entry.split('.')[0]
        ins = entry.split('.')[-1] if len(entry.split('.')) > 1 else 'app'
        app = getattr(__import__(mod), ins)
        #test any py file change
        begin_time = time.time()
        def is_file_modify(name):
            dirname = os.path.dirname(sys.modules[name].__file__)
            for fl in os.walk(dirname):
                for f in [f for f in fl[-1] if os.path.splitext(f)[1] == '.py']:
                    if os.stat(fl[0]+'/'+f).st_mtime > begin_time:
                        return True
        #watcher
        while True:
            del sys.modules[entry.split('.')[0]]
            app = __import__(entry.split('.')[0])
            app = getattr(app, entry.split('.')[-1])
            
            p = Process(target=app.run, args=(host, port, ))
            p.start()
            try:
                while True:
                    #if any file change, reload
                    if is_file_modify(app.name):
                        p.terminate()
                        begin_time = time.time()
                        print ('some file change, server reloading...')
                        break
                    time.sleep(0.01)
            except KeyboardInterrupt:
                p.terminate()
                exit(0)
                
if __name__ == "__main__":
    run_devserver()##cA5dR6Hn6kU6

