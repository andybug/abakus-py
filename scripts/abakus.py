#!/usr/bin/env python3

import argparse
import datetime
import io
import logging
import os
import re
import sys
import zlib

import nacl.encoding
import nacl.hash
from pyblake2 import blake2b
import yaml


#class AbakusFile:
#    def __init__(self, *args, **kwargs):
#        if 'fromObject' in kwargs:
#            obj = kwargs['fromObject']
#            self.path = obj['path']
#            self.hash = obj['hash']
#            self.mtime = obj['mtime']
#            self.ctime = obj['ctime']
#        elif 'absPath' in kwargs:
#            self.absPath = kwargs['absPath']
#            self.relPath = os.path.relpath(self.absPath, kwargs['root'])
#            self.mtime = os.path.getmtime(self.absPath)
#            self.ctime = os.path.getctime(self.absPath)
#            self.hash = self.__hash(self.absPath)
#            self.objPath = os.path.join(kwargs['root'], '.abakus/objects', self.hash)
#            self.__writeObject()
#            self.__writeObjectMetadata()
#
#    def __str__(self):
#        FORMAT = '%Y-%m-%d %H:%M:%S'
#        return '%s %s  %s' % (self.hash, datetime.datetime.fromtimestamp(self.mtime).strftime(FORMAT), self.relPath)
#
#    def __hash(self, path):
#        BUF_SIZE = 32768
#        hash = blake2b(digest_size=32)
#        with open(path, 'rb') as f:
#            for chunk in iter(lambda: f.read(BUF_SIZE), b''):
#                hash.update(chunk)
#        return hash.hexdigest()
#
#    def __writeObject(self):
#        BUF_SIZE = 32768
#        with open(self.absPath, 'rb') as rf:
#            with open(self.objPath, 'wb') as wf:
#                encoder = zlib.compressobj()
#                for chunk in iter(lambda: rf.read(BUF_SIZE), b''):
#                    wf.write(encoder.compress(chunk))
#                wf.write(encoder.flush())
#
#    def __writeObjectMetadata(self):
#        obj = {}
#        obj['type'] = 'FileMetadata'
#        obj['version'] = 1
#        obj['path'] = self.relPath
#        obj['hash'] = self.hash
#        obj['mtime'] = self.mtime
#        obj['ctime'] = self.ctime
#
#        BUF_SIZE = 32768
#        with open('%s.metadata' % self.objPath, 'wb') as f:
#            with io.StringIO() as stream:
#                yaml.dump(obj, stream, default_flow_style=False, indent=2)
#                f.write(zlib.compress(bytes(stream.getvalue(), 'utf8')))
#
#    def getObject(self):
#        o = {}
#        o['path'] = self.relPath
#        o['hash'] = self.hash
#        o['mtime'] = self.mtime
#        o['ctime'] = self.ctime
#        return o
#
#    def write(self, path):
#        obj = {}
#        obj['type'] = 'Index'
#        obj['version'] = 1
#        obj['files'] = []
#        for o in self.objList:
#            obj['files'].append(o.getObject())
#
#        with open(path, 'wb') as f:
#            with io.StringIO() as stream:
#                yaml.dump(obj, stream, default_flow_style=False, indent=2)
#                f.write(zlib.compress(bytes(stream.getvalue(), 'utf8')))
#
#    def read(self, path):
#        logging.info('Loading index from %s' % path)
#        with open(path, 'rb') as f:
#            indexFile = yaml.load(str(zlib.decompress(f.read()), 'utf8'))
#            if indexFile['type'] != 'Index':
#                logging.error('Expected type Index: %s' % path)
#            if indexFile['version'] != 1:
#                logging.error('Unknown Index version %d: %s' % (indexFile['version'], path))
#                exit(1)
#
#            for entry in indexFile['files']:
#               aFile = AbakusFile(root=self.root, fromObject=entry)
#               self.objList.append(aFile)


class AbakusMetadata:
    def __init__(self, root, **kwargs):
        if 'absPath' in kwargs:
            self.absPath = kwargs['absPath']
            self.relPath = os.path.relpath(self.absPath, root)
            self.mtime = int(round(os.path.getmtime(self.absPath)))
            self.ctime = int(round(os.path.getctime(self.absPath)))
            self.size = os.path.getsize(self.absPath)
            self.hash = self.__hash()

    def __str__(self):
        FORMAT = '%Y-%m-%d %H:%M:%S'
        return '%s %*d %s  %s' % (self.hash[:16], 12, self.size, datetime.datetime.fromtimestamp(self.mtime).strftime(FORMAT), self.relPath)

    def __repr__(self):
        return repr((self.relPath))

    def __hash(self):
        BUF_SIZE = 32768
        hash = blake2b(digest_size=32)
        with open(self.absPath, 'rb') as f:
            for chunk in iter(lambda: f.read(BUF_SIZE), b''):
                hash.update(chunk)
        return hash.hexdigest()


class AbakusFileList:
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
            excludeRules = AbakusFileList.ExcludeRules(path)
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
            excludeRules = AbakusFileList.ExcludeRules(path)
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
        self.fileList = []

        if 'dir' in kwargs:
            self.__addTree(kwargs['dir'])

    def __str__(self):
        lines = []
        for metadata in self.fileList:
            lines.append(str(metadata))
        return '\n'.join(lines)

    def __addTree(self, root):
        rulesStack = AbakusFileList.ExcludeRulesStack()
        rulesStack.pushRule(root, '/.abakus')
        self.__addSubTree(root, root, rulesStack)
        self.fileList = sorted(self.fileList, key=lambda metadata: metadata.relPath)

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
                self.fileList.append(metadata)

        excludeRules.popRules(current)


class AbakusBlobStore:
    def __init__(self, blobDir):
        self.blobDir = blobDir


class AbakusMetadataStore:
    def __init__(self, metadataDir):
        self.metadataDir = metadataDir


class AbakusSnapshotStore:
    def __init__(self, snapshotDir):
        self.snapshotDir = snapshotDir


class Abakus:
    def __init__(self, root):
        self.root = root
        self.homeDir = os.path.join(root, '.abakus')
        self.blobDir = os.path.join(self.homeDir, 'blob')
        self.metadataDir = os.path.join(self.homeDir, 'metadata')
        self.snapshotDir = os.path.join(self.homeDir, 'snapshot')

        self.blobStore = AbakusBlobStore(self.blobDir)
        self.metadataStore = AbakusMetadataStore(self.metadataDir)
        self.snapshotStore = AbakusSnapshotStore(self.snapshotDir)

    #def __find_root(self, dir):
    #    if dir == '/':
    #        return None
    #    home = os.path.join(dir, '.abakus')
    #    if os.path.isdir(home):
    #        return home
    #    __find_root(os.path.dirname(home))

    def cmd_init(self):
        if os.path.isdir(self.homeDir):
            logging.error('Already appears to be an abakus repo: %s' % self.root)
            exit(1)
        os.mkdir(self.homeDir)
        os.mkdir(self.blobDir)
        os.mkdir(self.metadataDir)
        os.mkdir(self.snapshotDir)

    def cmd_status(self):
        pass

    def cmd_snapshot(self):
        workdir = AbakusFileList(dir=self.root)
        print(workdir)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)

    abakus = Abakus(root=os.getcwd())

    ## argument parsing
    parser = argparse.ArgumentParser(prog='abakus')
    subparsers = parser.add_subparsers(help='subcommand help')

    init_parser = subparsers.add_parser('init', help='init abakus repo in current directory')
    init_parser.set_defaults(cmd_init=True)
    status_parser = subparsers.add_parser('status', help='show local changes')
    status_parser.set_defaults(cmd_status=True)
    snapshot_parser = subparsers.add_parser('snapshot', help='save changes to a new snapshot')
    snapshot_parser.set_defaults(cmd_snapshot=True)
    args = parser.parse_args()

    if 'cmd_init' in args:
        abakus.cmd_init()
    elif 'cmd_status' in args:
        abakus.cmd_status()
    elif 'cmd_snapshot' in args:
        abakus.cmd_snapshot()
