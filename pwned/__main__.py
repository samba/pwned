#!/usr/bin/env python3

from . import pwned

import argparse
import fileinput
import logging
import sys


logging.getLogger().setLevel(logging.DEBUG)


def request_debug(req):
    fmt = "{req.method} {req.full_url} {req.headers!r}"
    logging.debug("HTTP request: %s", fmt.format(req=req))

def reader(*names):
    if len(names) == 0:
        names = ['-']
    return fileinput.input(files=names, 
                           openhook=fileinput.hook_compressed)

def flatten(*items):
    queue = [items]
    while len(queue):
        s = queue.pop()
        if isinstance(s, (str, bytes)):
            yield s
        elif isinstance(s, (list, tuple)):
            queue.extend(s)
            continue
        else:
            yield s
            

def abbreviate(text):
    return text[0:3] + '...' + text[len(text) - 3:]

def checkpasswords(names, hashed=False):
    print("# Checking provided password lists for compromises...")
    with reader(*names) as r:
        for i, line in enumerate(r):
            line = line.strip()  # ignore surrounding whitespace
            try:
                status = pwned.checkpassword(line, hash=(not hashed))
            except pwned.HTTPError as e:
                logging.error(e)
                request_debug(e.request)
                continue
            if status > 0:
                print("Password #%d in %s is compromised %d times. (%s)" % (
                    i, r.filename(),  status, abbreviate(line)
                ))


def checkemails(names):
    print("# Checking provided email lists for compromised accounts...")
    with reader(*names) as r:
        for i, line in enumerate(r):
            line = line.strip()  # ignore surrounding whitespace
            try:
                print("# checking [%s]" % (line,))
                status = pwned.checkemail(line)
                print(line + " >> " + repr(status))
            except pwned.HTTPError as e:
                logging.error(e)
                request_debug(e.request)




def parse_args(args):
    parser = argparse.ArgumentParser(prog="pwned")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("--hashed", action="store_true", default=False)
    group.add_argument("--email", 
                       action="append", dest="email", nargs="*")
    group.add_argument("--password", "--passwd", 
                       action="append", dest="passwd", nargs="*")

    return parser.parse_args(args)

def main(args):
    args = parse_args(args)
    if args.passwd:
        checkpasswords(list(flatten(args.passwd)), hashed=args.hashed)
    if args.email:
        checkemails(list(flatten(args.email)))

if __name__ == "__main__":
    main(sys.argv[1:])