# -*- coding:utf-8 -*-
"""
@author: shijingjian
@date: 2020/3/10
"""

import base64
import time
import random
from urllib.parse import quote
import requests
import re
from binascii import b2a_hex
import rsa
import urllib3
urllib3.disable_warnings()

class WeiboSpider(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.session()
        self.session.headers = {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36',
        }
        self.session.verify = False #取消证书验证

    def get_su(self):
        su = base64.b64encode(self.username.encode()).decode()
        return su

    def get_nonce_pubkey_rsakv_servertime(self):
        su = self.get_su()
        _ = time.time()*1000
        prelogin_url = 'https://login.sina.com.cn/sso/prelogin.php?' \
                      'entry=account&callback=sinaSSOController.preloginCallBack&su={}&' \
                       'rsakt=mod&client=ssologin.js(v1.4.15)&_={}'.format(quote(su), _)
        resp = self.session.get(prelogin_url, verify=False).content.decode('utf-8')
        nonce = re.findall(r'"nonce":"(.*?)"', resp)[0]
        pubkey = re.findall(r'"pubkey":"(.*?)"', resp)[0]
        rsakv = re.findall(r'"rsakv":"(.*?)"', resp)[0]
        servertime = re.findall(r'"servertime":(.*?),', resp)[0]
        return nonce, pubkey, rsakv, servertime, su

    def get_sp(self):
        nonce, pubkey, rsakv, servertime, su = self.get_nonce_pubkey_rsakv_servertime()
        publickey = rsa.PublicKey(int(pubkey, 16), int('10001',16))
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(self.password)
        sp = b2a_hex(rsa.encrypt(message.encode(), publickey))
        return sp, nonce, pubkey, rsakv, servertime, su

    def login_weibo(self):
        sp, nonce, pubkey, rsakv, servertime, su = self.get_sp()
        login_url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
        data = {
            'entry': 'weibo',
            'gateway': '1',
            'from':'',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': 'https://login.sina.com.cn/crossdomain2.php?action=logout&r=https%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl%3D%252F',
            'vsnf': '1',
            'su': su,
            'service': 'miniblog',
            'servertime': str(int(servertime)+random.randint(1,20)),
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': sp,
            'sr': '1536 * 864',
            'encoding': 'UTF - 8',
            'prelt': '35',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META',
        }
        response = self.session.post(login_url, data=data, allow_redirects=False).content.decode('gbk')
        redirect_url = re.findall(r'location.replace\("(.*?)"\);', response)[0]  # 获取跳转的url
        result = self.session.get(redirect_url, allow_redirects=False).text  # 请求跳转页面
        ticket, ssosavestate = re.findall(r'ticket=(.*?)&ssosavestate=(.*?)"', result)[0]  # 获取ticket和ssosavestate参数
        uniqueid_url = 'https://passport.weibo.com/wbsso/login?ticket={}&ssosavestate={}&callback=sinaSSOController.doCrossDomainCallBack&scriptId=ssoscript0&client=ssologin.js(v1.4.19)&_={}'.format(
            ticket, ssosavestate, str(time.time()*1000))
        data = self.session.get(uniqueid_url).text  # 请求获取uid
        uniqueid = re.findall(r'"uniqueid":"(.*?)"', data)[0]
        home_url = 'https://weibo.com/u/{}/home?wvr=5&lf=reg'.format(uniqueid)  # 请求首页
        html = self.session.get(home_url)
        html.encoding = 'utf-8'
        print(html.text)

if __name__ == '__main__':
    username = 'xxx'
    password = 'xxx'
    spider = WeiboSpider(username, password)
    spider.login_weibo()