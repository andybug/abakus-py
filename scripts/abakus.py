#!/usr/bin/env python3

import argparse
import datetime
import io
import logging
import os
import re
import sys
import time
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
            self.metadataHash = self.__metadataHash()
            self.compressedHash = None

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
        return blake2b(input).hexdigest()

    def getShortHash(self):
        return self.hash[:16]

    def getShortMetadataHash(self):
        return self.metadataHash[:16]


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


class AbakusBlobStore:
    def __init__(self, abakus, blobDir):
        self.abakus = abakus
        self.blobDir = blobDir

    def add(self, metadata):
        logging.debug('Creating blob for %s (%s)' % (metadata.getShortHash(), metadata.relPath))
        return True


class AbakusMetadataStore:
    def __init__(self, abakus, metadataDir):
        self.abakus = abakus
        self.metadataDir = metadataDir

    def add(self, metadata):
        if os.path.isfile(os.path.join(self.metadataDir, metadata.metadataHash)):
            logging.debug('%s (%s) already exists in MetadataStore, skipping...' % (metadata.getShortMetadataHash(), metadata.relPath))
            return True
        if not self.abakus.blobStore.add(metadata):
            return False

        return self.__write(metadata)

    def __write(self, metadata):
        logging.debug('Writing metadata for %s (%s)' % (metadata.getShortMetadataHash, metadata.relPath))
        obj = {}
        obj['type'] = 'Metadata'
        obj['version'] = 1
        obj['relPath'] = metadata.relPath
        obj['hash'] = metadata.hash
        obj['mtime'] = metadata.mtime
        obj['ctime'] = metadata.ctime
        obj['size'] = metadata.size

        BUF_SIZE = 32768
        with open(os.path.join(self.metadataDir, metadata.metadataHash), 'wb') as f:
            with io.StringIO() as stream:
                yaml.dump(obj, stream, default_flow_style=False, indent=2)
                f.write(zlib.compress(bytes(stream.getvalue(), 'utf8')))

        return True


class AbakusSnapshotStore:
    def __init__(self, abakus, snapshotDir):
        self.abakus = abakus
        self.snapshotDir = snapshotDir

    def snapshot(self, metadataList):
        logging.info('Creating snapshot')
        snapshotTime = time.gmtime()

        for metadata in metadataList.list():
            self.abakus.metadataStore.add(metadata)


class Abakus:
    def __init__(self, root):
        self.root = root
        self.homeDir = os.path.join(root, '.abakus')
        self.blobDir = os.path.join(self.homeDir, 'blob')
        self.metadataDir = os.path.join(self.homeDir, 'metadata')
        self.snapshotDir = os.path.join(self.homeDir, 'snapshot')
        self.configPath = os.path.join(self.homeDir, 'config')

        self.loadConfig()

        self.blobStore = AbakusBlobStore(self, self.blobDir)
        self.metadataStore = AbakusMetadataStore(self, self.metadataDir)
        self.snapshotStore = AbakusSnapshotStore(self, self.snapshotDir)

    def loadConfig(self):
        try:
            with open(self.configPath, 'r') as f:
                config = yaml.load(f)
                if config['type'] != 'Config':
                    logging.error('Expected type Config: %s' % self.configPath)
                    exit(1)
                elif config['verison'] != 1:
                    logging.error('Unknown Config version %d: %s' % (config['version'], self.configPath))
                    exit(1)

                self.uuid = config['uuid']
        except:
            self.uuid = 'uninitialized'

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

        with open(os.path.join(self.home, 'config'), 'r') as f:
            config = yaml.load(f)

    def cmd_status(self):
        pass

    def cmd_snapshot(self):
        workdir = AbakusMetadataList(dir=self.root)
        self.snapshotStore.snapshot(workdir)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)

    abakus = Abakus(root=os.getcwd())

    # argument parsing
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
