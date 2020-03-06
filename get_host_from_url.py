#! /usr/bin/env python
# -*- coding:utf-8 -*-
# author:flystart
# home:www.flystart.org
# time:2020/2/21
import optparse
import sys
import urlparse

def put_file_contents(filename,contents):
    with open(filename,"ab+") as fin:
        fin.write(contents+"\n")


def get_file_content(filename):
    result = []
    f = open(filename, "r")
    for line in f.readlines():
        result.append(line.strip())
    f.close()
    return result


def url2host(url):
    parts = urlparse.urlparse(url)
    host = parts.netloc
    return host


def main():
    commandList = optparse.OptionParser('usage: %prog [-f store hosts file ]')
    commandList.add_option('-f', '--file', action='store',
                           help='Insert filename of stored hosts ::')
    commandList.add_option('-u', '--url', action="store",
              help="Insert TARGET URL: http[s]://www.victim.com[:PORT]",
            )
    options, remainder = commandList.parse_args()
    if (not options.file) and (not options.url):
        commandList.print_help()
        sys.exit(1)
    urls = [options.url] if options.url else get_file_content(options.file)
    for url in urls:
        host = url2host(url)
        if ":" in host:
            host = host.split(":")[0]
        print(host)
        put_file_contents("parse_hosts.txt",host)


if __name__ == "__main__":
    main()