#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import re
import sys

import nacl.encoding
import nacl.hash
from pyblake2 import blake2b
import yaml


class ExcludeRules:
    def __init__(self, directory):
        self.directory = directory
        self.rules = []

    def addRule(self, rule):
        if rule[0] == '/':
            rule = '^' + os.path.join(self.directory, rule[1:])
        else:
            rule = '^.*/' + rule

        rule = rule + '$'
        logging.debug('Added rule for %s: %s' % (self.directory, rule))
        self.rules.append(rule)

    def test(self, fileName):
        for rule in self.rules:
            if re.match(rule, fileName) != None:
                return True


class ExcludeRulesStack:
    def __init__(self):
        self.rules = []

    def pushRules(self, path):
        ignoreFilePath = os.path.join(path, '.abakusignore')
        excludeRules = ExcludeRules(path)
        try:
            with open(ignoreFilePath, 'r') as stream:
                ignoreFile = yaml.load(stream)
                if ignoreFile['type'] != 'IgnoreFile':
                    logging.error('Expected type IgnoreFile: %s' % f)
                if ignoreFile['version'] != 1:
                    logging.error('Unknown IgnoreFile version %d: %s' % (ignoreFile['version'], f))
                    exit(1)

                for exclude in ignoreFile['excludes']:
                    excludeRules.addRule(exclude)
        except IOError:
            pass

        self.rules.append(excludeRules)

    def pushRule(self, path, rule):
        excludeRules = ExcludeRules(path)
        excludeRules.addRule(rule)
        self.rules.append(excludeRules)

    def popRules(self, path):
        rules = self.rules.pop()
        if rules.directory != path:
            logging.error('Popped rules do not match directory: %s %s' % (rules.directory, path))
            exit(1)

    def test(self, fileName):
        for rule in self.rules:
            if rule.test(fileName):
                return True


class AbakusObject:
    def __init__(self, absPath, relPath):
        self.path = relPath
        self.hash = self.__hash(absPath)
        self.mtime = os.path.getmtime(absPath)

    def __str__(self):
        FORMAT = '%Y-%m-%d %H:%M:%S'
        return '%s %s  %s' % (self.hash, datetime.datetime.fromtimestamp(self.mtime).strftime(FORMAT), self.path)

    def __hash(self, path):
        BUF_SIZE = 4096
        hash = blake2b(digest_size=32)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(BUF_SIZE), b''):
                hash.update(chunk)
        return hash.hexdigest()


class AbakusObjectList:
    def __init__(self, root):
        logging.info('Creating hash tree at %s' % root)
        self.objList = []
        self.root = root
        rulesStack = ExcludeRulesStack()
        rulesStack.pushRule(root, '/.abakus')
        self.__addTree(root, rulesStack)

    def __str__(self):
        lines = []
        for obj in self.objList:
            lines.append(str(obj))
        return '\n'.join(lines)

    def __addTree(self, root, excludeRules):
        excludeRules.pushRules(root)
 
        for f in os.listdir(root):
            f = os.path.join(root, f)
            if excludeRules.test(f):
                continue

            if os.path.isdir(f):
                self.__addTree(f, excludeRules)
            elif os.path.isfile(f):
                obj = AbakusObject(f, os.path.relpath(f, self.root))
                self.objList.append(obj)

        excludeRules.popRules(root)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
    cwd = os.getcwd()
    tree = AbakusObjectList(cwd)
    print(tree)
