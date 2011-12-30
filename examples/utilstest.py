#coding=utf8
########工具测试例子

from soxo import *
co = Soxo()
co.debug = True


#-----test permissions----------------------------
from utils.perm import *

def valid(self):
    if g.user == 'true':
        return Role('auth')
    return Role('guest')
    
Identity.valid = valid

auth_perm = Permission(Role('auth'), Role('admin'))

@co.route('/m/<str:ab>/')
@co.route('/m/<str:ab>/<int:page>/')
@auth_perm.require(401)
def permtest(ab, page=1):
    return ab + str(page) + '-------------', url_for('.permtest', ab='zz', page=100)


#in before_handler, after_handler; you can operate request, session,..., too
@co.before_request()
def test_before():
    #print 'before_handler=========', request.path, g.user
    #if set g.user permtest will return something, else return 401 exception
    g.user = 'true'
    #request.path = 'xx00'

#--------test session---------------------------------------
import redis
co.redis = {'host':'localhost', 'port':6379, 'db':0}
@co.route('/ses/')
def ses_set():
    print session, type(session)
    session['_id'] = 'abcdefg'
    print 'session data _id==', session['_id']
    return session['_id']
    
@co.route('/ses/get/')
def ses_get():
    return session.get('_id', 'empty')#session['_id']

@co.route('/ses/del/')
def ses_del():
    return session.pop('_id', 'nothing')
#--------test wtf-------------------------------------------
from utils.wtf import Form, TextField, SubmitField, required

class MyForm(Form):
    title = TextField(u"活动标题",validators=[required(message=u"必填")])
    submit = SubmitField(u'提交')
    
@co.route('/form/', methods=('GET', 'POST'))
def formtest():
    form = MyForm(request, csrf_session_key='my session key', csrf_enabled=True)#add to app config
    print 'valid form==', form.is_submitted(), form.is_valid(), form.csrf.validate(form), form.title.validate(form)
    if form.validate_on_submit():
        pass
    return render('form.html', form=form)
    
