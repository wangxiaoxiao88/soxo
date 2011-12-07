#coding=utf-8
class Temp:
	def __init__(self,ns):
		for k in ns.keys():
			globals()[k] = ns[k]
		self.html = []


		self.html.append( """""")
		self.html.append( """<a>""")
		self.html.append( str(test))
		self.html.append( """</a>
<img src='/static/tifa.jpg' />
""")
	def __call__(self):
		return self.html