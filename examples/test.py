#coding=utf8
########更多功能测试的例子
#--test qstr class
#qstr = QueryString('2=3&a=4&a=5&3=1&b=3')
#print qstr.data
#print qstr.get('a'), qstr.get('4', 0), qstr.get('b', 0, int)
#print qstr.get_list('a'), qstr.get_list('a', [], int), qstr.get_list('e', []), qstr.get_list('bb')#, qstr.get_list('2')
#exit()

#you only need to use "from soxo import *"; see the __all__
from soxo import *
co = Soxo()
#----test url args
@co.route('/abc/<int:xx>/')
def test(xx):
    print xx, type(xx)
    print request, cookie, query_str
    return 'abc'
@co.route('/123/<float:yy>/')
class TestView(BaseView):
    def get(self, yy):
        print yy
        return '123', request.path
    def post(self, yy):
        pass
#----test url_for and module url_for
@co.route('/url/for/')
def urltest():
    print url_for('.TestView', yy=3.3)
    print request.environ['SERVER_NAME'], request.environ['SERVER_PROTOCOL'], \
            request.environ['SERVER_PORT']
    return ''.join((url_for('.test', xx=22), request.environ['SERVER_NAME'], request.environ['SERVER_PROTOCOL'], \
            request.environ['SERVER_PORT']))

mod = Module('mod')
@mod.route('/tt/<int:oo>/')
def tto(oo):
    print '#############'
    print render, url_for, request, cookie, query_str
    return url_for('mod.tto', oo=222)

#----test render and Template
@co.route('/render/')
def tpl():
    ns={'x':8,'test':"test include tag",'shit':True,'fuck':False, \
            'name':'your name is:', 'value':"29", \
            'dicts':[(2,"2"),(3,"3"),(4,"4")],'keys':(1,2,3,4), \
            'val':"what the fuck"}
    
    tpl = Template("templates/tpl2.html")#if use Template, tpl config useless
    return tpl(test='ooxx')
    #return render('tpl.html', **ns)
    
@co.route('/filter/')
def fil():
    return render('tpl_filter.html', a='2222')
    
@co.route('/block/')
def block():
    return render('sub.html')
    
@co.route('/block2/')
def block():
    return render('sub2.html')
#----test cookie
@co.route('/w/')
def wc():
    cookie['abc'] = 222
    cookie['yy'] = 'ooxx'
    cookie['abc']['expires'] = 1800
    #cookie['abc']['expires'] = 1800
    return 'write abc==222'

@mod.route('/r/')
def rc():
    print cookie['abc']
    return 'read abc==' + str(cookie['abc'])
#----test session, you must install memcache and python-memcache or redis and pyredis

#co.memcache = ['127.0.0.1:11211']
@co.route('/sw/')
def sw():
    session['oo'] = 'xx'
    return 'ooxx w'

@mod.route('/sr/')
def sr():
    print session['oo']
    return 'r ooxx: ' + session['oo']

#----test redirect
@co.route('/redirect/')
def transfer():
    print 'redirecting ...'
    return redirect( url_for('.tpl'))
#----test query string
@co.route('/qstr/')
def qstr():
    print query_str['abc']
    return query_str['xx']
@co.route('/qd/')
def qstr2():
    print query_str.get('abc')
    return 'ooxx'

#-----test multi route urls
@mod.route('/m/<str:ab>/')
@mod.route('/m/<str:ab>/<int:page>/')
def multi(ab, page=1):
    return ab + str(page) + '-------------', url_for('mod.multi', ab='zz', page=100)

#route first, register later
co.register_module('/mod', mod)#, 'xxx')

#error handler test, when http error(404,500) occur, before_request and after request don't invole
@co.error_404()#
def test404():
    #print g.user#None
    return request.path, '--------404'
    
#@co.before_request()#in before_handler, after_handler; you can operate request, session,..., too
#def test_before():
#    print 'before_handler', request.path, g.user
#    request.path = 'xx00'
        
co.debug = True
co.run_cherrypy_server()#use cherrypy wsgi server

