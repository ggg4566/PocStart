#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2020/6/15


import queue
import argparse
import threading
import time
import sys
import os
import logging
import imp
import glob
import traceback


logging.basicConfig(level = logging.INFO,format = '%(message)s')
logger = logging.getLogger(__name__)

paths = {'SCRIPT_PATH':'',
         'ROOT_PATH':''
         }
conf = {'targets':list(),
        'pocs':list(),
        'poc_mode':{},
        'outfile':'',
        'mode':'',
        'thread_num':1,
        'total_num':0,
        'is_scaned':0}
COLOR ={'red':'\033[1;31;40m',
        'white':'\033[1;37;40m',
        'blue':'\033[1;34;40m',
        'yellow':'\033[1;33;40m',
        'general':'\033[1;32;40m',
        'normal':'\033[0m'}


class ScanHandler(object):
    def __init__(self, task_queue, task_handler, result_queue=None, thread_count=1, *args, **kwargs):
        self.task_queue = task_queue
        self.task_handler = task_handler
        self.result_queue = result_queue
        self.thread_count = thread_count
        self.args = args
        self.kwagrs = kwargs
        self.thread_pool = []

    def run(self):
        for i in range(self.thread_count):
            t = _TaskHandler(self.task_queue, self.task_handler, self.result_queue, *self.args, **self.kwagrs)
            self.thread_pool.append(t)
        for th in self.thread_pool:
            th.setDaemon(True)
            th.start()

        while self._check_stop():
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                print('KeyboardInterruption')
                self.stop_all()
                break
        logging.info(COLOR['white']+'[+] >>>ALL Task Finshed.')

    def _check_stop(self):
        finish_num = 0
        for th in self.thread_pool:
            if not th.isAlive():
                finish_num += 1

        return False if finish_num == len(self.thread_pool) else True

    def stop_all(self):
        for th in self.thread_pool:
            th.stop()


class _TaskHandler(threading.Thread):

    def __init__(self, task_queue, task_handler, result_queue=None, *args, **kwargs):
        threading.Thread.__init__(self)
        self.task_queue = task_queue
        self.task_handler = task_handler
        self.result_queue = result_queue
        self.args = args
        self.kwargs = kwargs
        self.is_stoped = True


    def run(self):
        while self.is_stoped:
            try:
                item = self.task_queue.get(False)  # block= False
                poc = item['poc']
                target = item['target']
                mode = conf['mode']
                poc_name = os.path.basename(poc)
                mod_obj = conf['poc_mode'][poc_name]
                if target:
                    res = {}
                    if mode == 'verify':
                        res = mod_obj.verify(target)
                    if mode == 'attack':
                        res = mod_obj.attack(target)
                    conf['is_scaned'] = conf['is_scaned'] + 1
                    if res:
                        if res['Success']:
                            info = COLOR['red'] +'[*] '+ poc_name + "|" + target['target'] + "|Success|" + res[
                                'Info']
                            logger.info(info)
                        else:
                            info = COLOR['general']+ '[*] '+ poc_name + "|" + target[
                                'target'] + "|Fail|Not Found Vulnerability:("
                            logger.info(info)
                logger.info(COLOR['yellow'] + '[*] Scan Process: Already Scaned/Totals:{0}/{1}'.format(conf['is_scaned'],
                                                                                                    conf[
                                                                                                        'total_num']))
                self.task_handler(info, self.result_queue, *self.args, **self.kwargs)
                self.task_queue.task_done()  # 退出queue
            except queue.Empty as e:
                break
            except Exception as e:
                logger.error(traceback.format_exc())
                logging.info(COLOR['general']+str(e))
            # time.sleep(1)

    def stop(self):
        self.is_stoped = False


def out(item, result_queue):
    result_queue.put(item)


def put_file_contents(filename,contents):
    with open(filename,"a+") as fin:
        fin.write(contents+'\n')


def get_file_content(filename):
    result = []
    f = open(filename, "r")
    for line in f.readlines():
        result.append(line.strip())
    f.close()
    return result


def cmdline_parser():
    parser = argparse.ArgumentParser(description='powered by flystart <mail:root@flystart.org> ',
                                     usage='python %(prog)s -iS[-iF] target [-p port] -s exp [-m mode] [-o result.txt] [-t 5]',
                                     add_help=False)
    script = parser.add_argument_group('SCRIPT')
    script.add_argument('-s', metavar='NAME', dest="script_name", type=str, default='',
                        help='load script by name (-s ./tomcat/poc.py) or path (-s ./tomcat)')

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


def init_options(args):
    conf['mode']=args['mode']
    if args['target_single']:
        conf['total_num']= 1
        node = {'target': '', 'port': '', 'param': ''}
        node['port'] = args['target_port']
        node['param'] = args['poc_param']
        node['target'] = args['target_single']
        conf['targets'].append(node)
    if args['target_file']:
        targets = get_file_content(args['target_file'])
        for target in targets:
            node = {'target': '', 'port': '', 'param': ''}
            node['port'] = args['target_port']
            node['param'] = args['poc_param']
            node['target'] = target
            conf['targets'].append(node)
    paths['SCRIPT_PATH'] = paths['ROOT_PATH'] + "/pocs/"+ args['script_name']
    input_path =  paths['SCRIPT_PATH']
    conf['pocs'] = get_pocs(input_path)
    conf['total_num'] = len(conf['targets'])* len(conf['pocs'])
    conf['outfile'] = args['output_path']
    conf['thread_num'] = args['thread_num']


def init_modle(pocs):
    for poc in pocs:
        mode = load_module(poc)
        name = os.path.basename(poc)
        conf['poc_mode'].update({name:mode})
    return


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


def load_module(poc):
    _name =os.path.split(poc)[-1]
    path = os.path.split(poc)[0]
    msg = '\033[1;32;40m[+] Load custom script:\033[1;32;40m%s' % _name
    logger.info(msg)

    fp, pathname, description = imp.find_module(os.path.splitext(_name)[0], [path])
    try:
        module_obj = imp.load_module("_", fp, pathname, description)
        for each in ['verify','attack']:
            if not hasattr(module_obj, each):
                errorMsg = "Can't find essential method:'%s()' in current script，Please modify your script/PoC."
                logger.info(errorMsg)
    except ImportError as e:
        errorMsg = "Your current scipt [%s.py] caused this exception\n%s\n%s" \
                   % (_name, '[Error Msg]: ' + str(e), 'Maybe you can download this module from pip or easy_install')
        logger.info(errorMsg)
    except Exception:
        logger.error(traceback.format_exc())
        logger.warning('It seems like you reached a unhandled exception!!!')
        logger.info(Exception)
    return  module_obj


def init_tasks(conf):
    targets = conf['targets']
    pocs = conf['pocs']
    ret = []
    for poc in pocs:
        for target in targets:
            ret.append({'target':target,'poc':poc})
    return ret


def main():
    banner = '''
        ____             _____ __             __     
       / __ \____  _____/ ___// /_____ ______/ /_    
      / /_/ / __ \/ ___/\__ \/ __/ __ `/ ___/ __/    
     / ____/ /_/ / /__ ___/ / /_/ /_/ / /  / /_      
    /_/    \____/\___//____/\__/\__,_/_/   \__/      

        version:1.0.3
        author:flystart  email:root@flystart.org
        team:www.ms509.com
        '''

    logger.info(COLOR['blue'] + banner + COLOR['general'])
    try:
        cmdLineOptions = cmdline_parser().__dict__
        paths['ROOT_PATH'] = os.path.dirname(os.path.realpath(__file__))
        try:
            os.path.isdir(paths['ROOT_PATH'])
        except UnicodeEncodeError:
            errMsg = "your system does not properly handle non-ASCII paths. "
            errMsg += "Please move the project root directory to another location"
            logger.error(errMsg)
            raise SystemExit
        init_options(cmdLineOptions)
        tasks = init_tasks(conf)
        init_modle(conf['pocs'])
        task_queue = queue.Queue()
        for task in tasks:
            task_queue.put(task)
        out_queue = queue.Queue()
        ScanHandler(task_queue, out, out_queue, conf['thread_num']).run()
        logging.info('[+] Print Scan Result:')
        while True:
            scan_info = out_queue.get()
            put_file_contents(conf['outfile'],scan_info)
            logging.info(scan_info)
            if out_queue.empty():
                break
        logging.info(COLOR['normal'])

    except Exception:
        logger.error(traceback.format_exc())
        logger.warning('It seems like you reached a unhandled exception!!!')


if __name__ == '__main__':
    main()