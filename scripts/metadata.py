#!/usr/bin/env python3

import logging
import os
import re

from pyblake2 import blake2b
import yaml


class AbakusMetadata:
    def __init__(self, root, **kwargs):
        if 'absPath' in kwargs:
            self.absPath = kwargs['absPath']
            self.relPath = os.path.relpath(self.absPath, root)
            self.mtime = int(round(os.path.getmtime(self.absPath)))
            self.ctime = int(round(os.path.getctime(self.absPath)))
            self.size = os.path.getsize(self.absPath)
            self.hash = self.__hash()
            self.metadataHash = self.__metadataHash()
        elif 'obj' in kwargs:
            obj = kwargs['obj']
            self.absPath = os.path.join(root, obj['relPath'])
            self.relPath = obj['relPath']
            self.mtime = obj['mtime']
            self.ctime = obj['ctime']
            self.size = obj['size']
            self.hash = obj['hash']
            self.metadataHash = self.__metadataHash()
            if 'cHash' in obj:
                self.cHash = obj['cHash']
            if 'cSize' in obj:
                self.cSize = obj['cSize']

    def __str__(self):
        FORMAT = '%Y-%m-%d %H:%M:%S'
        return '%s %*d %s  %s' % (self.getShortHash(), 12, self.size, datetime.datetime.fromtimestamp(self.mtime).strftime(FORMAT), self.relPath)

    def __repr__(self):
        return repr((self.relPath))

    def __hash(self):
        BUF_SIZE = 32768
        hash = blake2b(digest_size=32)
        with open(self.absPath, 'rb') as f:
            for chunk in iter(lambda: f.read(BUF_SIZE), b''):
                hash.update(chunk)
        return hash.hexdigest()

    def __metadataHash(self):
        input = bytearray('%s%s%d%d%d' % (self.hash, self.relPath, self.ctime, self.mtime, self.size), 'utf8')
        return blake2b(input, digest_size=32).hexdigest()

    def isCached(self):
        if hasattr(self, 'cHash') and hasattr(self, 'cSize'):
            return True
        return False

    def getShortHash(self):
        return self.hash[:16]

    def getShortMetadataHash(self):
        return self.metadataHash[:16]

    def getFileObject(self):
        if not self.isCached():
            logging.error('Cannot create file object - not cached (%s)' % self.relPath)
            return None

        obj = {}
        obj['type'] = 'FileMetadata'
        obj['version'] = 1
        obj['relPath'] = self.relPath
        obj['hash'] = self.hash
        obj['mtime'] = self.mtime
        obj['ctime'] = self.ctime
        obj['size'] = self.size
        obj['cHash'] = self.cHash
        obj['cSize'] = self.cSize
        return obj


class AbakusMetadataList:
    class ExcludeRules:
        def __init__(self, dir):
            self.dir = dir
            self.rules = []

        def addRule(self, rule):
            if rule[0] == '/':
                rule = '^' + os.path.join(self.dir, rule[1:])
            else:
                rule = '^.*/' + rule

            rule = rule + '$'
            logging.debug('Added rule for %s: %s' % (self.dir, rule))
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
            excludeRules = AbakusMetadataList.ExcludeRules(path)
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
            excludeRules = AbakusMetadataList.ExcludeRules(path)
            excludeRules.addRule(rule)
            self.rules.append(excludeRules)

        def popRules(self, path):
            rules = self.rules.pop()
            if rules.dir != path:
                logging.error('Popped rules do not match directory: %s %s' % (rules.dir, path))
                exit(1)

        def test(self, fileName):
            for rule in self.rules:
                if rule.test(fileName):
                    return True


    def __init__(self, **kwargs):
        self.metadataList = []

        if 'dir' in kwargs:
            self.__addTree(kwargs['dir'])

    def __str__(self):
        lines = []
        for metadata in self.metadataList:
            lines.append(str(metadata))
        return '\n'.join(lines)

    def __addTree(self, root):
        rulesStack = AbakusMetadataList.ExcludeRulesStack()
        rulesStack.pushRule(root, '/.abakus')
        self.__addSubTree(root, root, rulesStack)
        self.metadataList = sorted(self.metadataList, key=lambda metadata: metadata.relPath)

    def __addSubTree(self, root, current, excludeRules):
        excludeRules.pushRules(current)

        for f in os.listdir(current):
            f = os.path.join(current, f)
            if excludeRules.test(f):
                continue

            if os.path.isdir(f):
                self.__addSubTree(root, f, excludeRules)
            elif os.path.isfile(f):
                metadata = AbakusMetadata(root, absPath=f)
                self.metadataList.append(metadata)

        excludeRules.popRules(current)

    def list(self):
        return self.metadataList

    def add(self, metadata):
        self.metadataList.append(metadata)
