#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2020/2/21


import os
import sys
import traceback
import argparse
import logging
import imp
import glob
from multiprocessing.dummy import Lock
from multiprocessing.dummy import Pool as ThreadPool

logging.basicConfig(level = logging.INFO,format = '%(message)s')
logger = logging.getLogger(__name__)

paths = {'SCRIPT_PATH':'',
         'ROOT_PATH':''
         }
conf = {'targets':list(),
        'pocs':list(),
        'outfile':'',
        'mode':'',
        'thread_num':1,
        'total_num':0,
        'is_scaned':0}

mutex = Lock()

def put_file_contents(filename,contents):
    with open(filename,"ab+") as fin:
        fin.write(contents+'\n')


def get_file_content(filename):
    result = []
    f = open(filename, "r")
    for line in f.readlines():
        result.append(line.strip())
    f.close()
    return result


def check_target(target):
    if not "http" in target.strip():
        target = 'http://' + target
    return target



def loadModule(poc):
    _name =os.path.split(poc)[-1]
    path = os.path.split(poc)[0]
    # _name = CONFIG.MODULE_NAME
    msg = '\033[1;33m[+] Load custom script:\033[1;33m%s' % _name
    logger.info(msg)

    fp, pathname, description = imp.find_module(os.path.splitext(_name)[0], [path])
    try:
        module_obj = imp.load_module("_", fp, pathname, description)
        for each in ['poc']:
            if not hasattr(module_obj, each):
                errorMsg = "Can't find essential method:'%s()' in current script，Please modify your script/PoC."
                sys.exit(logger.info(errorMsg))
    except ImportError, e:
        errorMsg = "Your current scipt [%s.py] caused this exception\n%s\n%s" \
                   % (_name, '[Error Msg]: ' + str(e), 'Maybe you can download this module from pip or easy_install')
        sys.exit(logger.info(errorMsg))
    return  module_obj


def cmdLineParser():
    parser = argparse.ArgumentParser(description='powered by flystart <mail:root@flystart.org> ',
                                     usage='python %(prog)s -iS[-iF] target [-p port] -s exp [-m mode] [-o result.txt] [-t 5]',
                                     add_help=False)
    script = parser.add_argument_group('SCRIPT')
    script.add_argument('-s', metavar='NAME', dest="script_name", type=str, default='',
                        help='load script by name (-s ./pocs/tomcat/poc.py) or path (-s ./pocs/tomcat)')

    target = parser.add_argument_group('TARGET')
    target.add_argument('-iS', metavar='TARGET', dest="target_single", type=str, default='',
                        help="scan a single target (e.g. www.wooyun.org)")
    target.add_argument('-iF', metavar='FILE', dest="target_file", type=str, default='',
                        help='load targets from targetFile (e.g. ./data/wooyun_domain)')
    target.add_argument('-p', metavar='PORT', dest="target_port", type=int,
                        help='target port (e.g. 8080)')
    target.add_argument('-param', metavar='POC Extra Param', dest="poc_param", type=str,default='',
                        help='extra poc param (e.g execute cmd | download file name, only set a param)')
    output = parser.add_argument_group('OUTPUT')
    output.add_argument('-o', metavar='FILE', dest="output_path", type=str, default='out_result.txt',
                        help='output file path&name. default in ./output/')
    system = parser.add_argument_group('SYSTEM')
    system.add_argument('-h', '--help', action='help',
                        help='show this help message and exit')
    mode= parser.add_argument_group('MODE')
    mode.add_argument('-m', metavar='MODE', dest="mode", type=str, default='verify',
                        help="set verify mode[verify|attack]")
    mode.add_argument('-t', metavar='THREADS', dest="thread_num", type=int, default='2',
                        help="set thread numners default is 2")
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args


def initOptions(args):
    conf['mode']=args['mode']
    if args['target_single']:
        node = {'target': '', 'port': '', 'param': ''}
        node['port'] = args['target_port']
        node['param'] = args['poc_param']
        node['target'] = args['target_single']
        conf['targets'].append(node)
    if args['target_file']:
        targets = get_file_content(args['target_file'])
        conf['total_num'] = len(targets)
        for target in targets:
            node = {'target': '', 'port': '', 'param': ''}
            node['port'] = args['target_port']
            node['param'] = args['poc_param']
            node['target'] = target
            conf['targets'].append(node)

    paths['SCRIPT_PATH'] = paths['ROOT_PATH'] + "/pocs/"+ args['script_name']
    input_path =  paths['SCRIPT_PATH']
    conf['pocs'] = get_pocs(input_path)
    conf['outfile'] = args['output_path']
    conf['thread_num'] = args['thread_num']


def get_pocs(input_path):
    pocs = []
    poc_path = input_path
    if input_path.endswith('.py'):
        pocs.append(input_path)
    elif os.path.exists(poc_path):
        pyFiles = glob.glob(os.path.join(poc_path, "*.py"))
        pocs = pyFiles
    else:
        msg = 'Script [%s] not exist. Use a available script in ./pocs/' % input_path
        sys.exit(logger.error(msg))
    if not pocs:
        msg = 'Script [%s] not found. Use a available script in ./pocs/' % input_path
        sys.exit(logger.error(msg))
    return pocs


def task(target):
    mutex.acquire()
    pocs = conf['pocs']
    out_file = conf['outfile']
    mode = conf['mode']
    conf['is_scaned'] = conf['is_scaned'] + 1
    mutex.release()
    for poc in pocs:
        try:
            poc_name = os.path.basename(poc)
            mod_obj = loadModule(poc)
            if target:
                res = mod_obj.poc(target, mode)
                if res :
                    if res['Success']:
                        info = "\033[1;31m[*] " + poc_name + "|" + target['target'] + "|Success|" + res['Info'] +"\033[1;31m"
                        logger.info(info)
                        put_file_contents(out_file, info)
                    else:
                        info = "\033[1;31m[*] " + poc_name + "|" + target['target'] + "|Fail|Not Found Vulnerability:("+"\033[1;31m[*] "
                        logger.info(info)
        except Exception as e:
            logger.error(e.message)
            pass
    logger.info('\033[1;34m[*] ' + 'Scan Process: Already Scaned/Totals:{0}/{1}'.format(conf['is_scaned'],conf['total_num']) + '\033[1;34m')
    return


def run(targets,threads):
    try:
        # 线程数
        pool = ThreadPool(processes=threads)
        # get传递超时时间，用于捕捉ctrl+c
        pool.map_async(task,targets).get(0xffff)
        pool.close()
        pool.join()
    except Exception as e:
        logger.error(e.message)
    except KeyboardInterrupt:
        logger.info(u'\n[-] 用户终止扫描...')
        sys.exit(1)


def main():
    banner = '''
    ____             _____ __             __     
   / __ \____  _____/ ___// /_____ ______/ /_    
  / /_/ / __ \/ ___/\__ \/ __/ __ `/ ___/ __/    
 / ____/ /_/ / /__ ___/ / /_/ /_/ / /  / /_      
/_/    \____/\___//____/\__/\__,_/_/   \__/      
                                                 
                    mailto:root@flystart.org
    			'''

    logger.info('\033[1;34m' + banner + '\033[0m')
    try:
        cmdLineOptions = cmdLineParser().__dict__
        paths['ROOT_PATH'] = os.path.dirname(os.path.realpath(__file__))
        try:
            os.path.isdir(paths['ROOT_PATH'])
        except UnicodeEncodeError:
            errMsg = "your system does not properly handle non-ASCII paths. "
            errMsg += "Please move the project root directory to another location"
            logger.error(errMsg)
            raise SystemExit
        initOptions(cmdLineOptions)
        run(conf['targets'],conf['thread_num'])

    except Exception:
        logger.error(traceback.format_exc())
        logger.warning('It seems like you reached a unhandled exception!!!')

if __name__ == "__main__":
    main()
