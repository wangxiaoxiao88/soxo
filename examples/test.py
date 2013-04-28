#coding=utf8
from soxo import *
import redis

config = {
        'static': '/home/sx/docs/soxo/examples/static',
        'template_dir': 'templates',    #os.path.join('/static', 'abc/123.jpg')
        'cookie_expires': 24*30*60,     #one day
        'session_expires': 1800,        #30*60, if cookie_expires < session_expires, s_e = c_e
        'secret_key': '',               #use to session hmac serect & csrf_session_key
        'csrf_enabled': True,
        'domain': 'test.com',           #domain without www and subdomain
        'redis': None                   #redis.Redis(host='localhost', port=6379, db=0)
}

co = Soxo(config=config)

#---test route-------------
@co.route('/123/<float:yy>/')
class TestView(BaseView):
    def get(self, yy):
        print yy, self.g.test, self.g
        return '123', 
    def post(self, yy):
        pass
#---test handlers--------------------
@co.error_404()#
def test404(request):
    return request.path, '--------404'
        
@co.before_request()
def before_request(request):
    request.g.test = 2
    print request.g
#---test url_for-----------------
@co.route('/123/')
class Test1View(BaseView):
    def get(self):
        print url_for('.TestView', yy=5.2)
        return '123', 
#---test session-----------------
@co.route('/s/1/')
class TestS1View(BaseView):
    def get(self):
        self.request.session['a'] = 444
        return '123', 
@co.route('/s/2/')
class TestS2View(BaseView):
    def get(self):
        print self.request.session['a']
        return '123', 
#---test qstr-------------
@co.route('/q/')
class TestqView(BaseView):
    def get(self):
        print self.request.qstr.aaa, self.config
        return '123', 
#---test module-------------
mod = Module('mod')
co.register_module('/m', mod)
@mod.route('/q/')
class TestmView(BaseView):
    def get(self):
        print self.request.qstr.aaa, self.session['a']
        return '123', 
#---test tpl-------------
@mod.route('/tpl/')
class TesttplView(BaseView):
    def get(self):
        print self.request.qstr.aaa, self.config
        return render('jinja2.html', request=self.request)
#---test redirect---------
@mod.route('/r/')
class TestrView(BaseView):
    def get(self):
        return redirect(url_for('.TestView', yy=22.0))
#---test debug--------
@mod.route('/r2/')
class Testr2View(BaseView):
    def get(self):
        a = 3
        raise u'哈哈哈'
        return redirect(url_for('.TestView', yy=22.0))
#---test static--------
@mod.route('/s/')
class TestsView(BaseView):
    def get(self):
        return render('static.html', request=self.request)

co.debug = True
co.run()

