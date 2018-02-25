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



class AbakusFileMetadata:
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


class AbakusFileMetadataList:
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
            excludeRules = AbakusFileMetadataList.ExcludeRules(path)
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
            excludeRules = AbakusFileMetadataList.ExcludeRules(path)
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
        rulesStack = AbakusFileMetadataList.ExcludeRulesStack()
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
                metadata = AbakusFileMetadata(root, absPath=f)
                self.metadataList.append(metadata)

        excludeRules.popRules(current)

    def list(self):
        return self.metadataList

    def add(self, metadata):
        self.metadataList.append(metadata)


class AbakusDiff:
    def __init__(self, old, new):
        self.added = []
        self.removed = []
        self.changed = []

        oldMap = {}

        for metadata in old.list():
            oldMap[metadata.relPath] = (metadata, False)

        for metadata in new.list():
            if not metadata.relPath in oldMap:
                self.added.append(metadata)
                continue
            (oldMetadata, _) = oldMap[metadata.relPath]
            oldMap[metadata.relPath] = (oldMetadata, True)
            if not oldMetadata.metadataHash == metadata.metadataHash:
                self.changed.append(metadata)

        for relPath, (metadata, inNew) in oldMap.items():
            if not inNew:
                self.removed.append(metadata)

    def __str__(self):
        with io.StringIO() as f:
            if len(self.added) > 0:
                f.write('Added:\n')
                for a in self.added:
                    f.write(str(a))
                    f.write('\n')
                f.write('\n')

            if len(self.removed) > 0:
                f.write('Removed:\n')
                for a in self.removed:
                    f.write(str(a))
                    f.write('\n')
                f.write('\n')

            if len(self.changed) > 0:
                f.write('Changed:\n')
                for a in self.changed:
                    f.write(str(a))
                    f.write('\n')

            return f.getvalue()


class AbakusBlobStore:
    def __init__(self, abakus, blobDir):
        self.abakus = abakus
        self.blobDir = blobDir

    def add(self, metadata):
        logging.debug('Creating blob for %s (%s)' % (metadata.getShortHash(), metadata.relPath))
        blobPath = os.path.join(self.blobDir, metadata.hash)
        hash = blake2b(digest_size=32)
        BUF_SIZE = 32768

        if os.path.isfile(blobPath):
            logging.debug('%s (%s) already exists in BlobStore, just hashing...' % (metadata.getShortHash(), metadata.relPath))
            with open(blobPath, 'rb') as f:
                for chunk in iter(lambda: f.read(BUF_SIZE), b''):
                    hash.update(chunk)
        else:
            with open(metadata.absPath, 'rb') as rf:
                with open(blobPath, 'wb') as wf:
                    encoder = zlib.compressobj()
                    for chunk in iter(lambda: rf.read(BUF_SIZE), b''):
                        cChunk = encoder.compress(chunk)
                        wf.write(cChunk)
                        hash.update(cChunk)
                    wf.write(encoder.flush())

        metadata.cHash = hash.hexdigest()
        metadata.cSize = os.stat(blobPath).st_size


class AbakusMetadataStore:
    def __init__(self, abakus, metadataDir):
        self.abakus = abakus
        self.metadataDir = metadataDir

    def add(self, metadata):
        if os.path.isfile(os.path.join(self.metadataDir, metadata.metadataHash)):
            logging.debug('%s (%s) already exists in MetadataStore, loading...' % (metadata.getShortMetadataHash(), metadata.relPath))
            return self.__read(metadata.metadataHash)

        self.abakus.blobStore.add(metadata)
        self.__write(metadata)

    def load(self, metadataHash):
        return self.__read(metadataHash)

    def __read(self, metadataHash):
        metadataPath = os.path.join(self.metadataDir, metadataHash)
        with open(metadataPath, 'rb') as f:
            metadataFile = yaml.load(str(zlib.decompress(f.read()), 'utf8'))
            if metadataFile['type'] != 'FileMetadata':
                logging.error('Expected type FileMetadata: %s' % metadataPath)
                exit(1)
            if metadataFile['version'] != 1:
                logging.error('Unknown FileMetadata version %d: %s' % (metadataFile['version'], metadataPath))
                exit(1)
            return AbakusFileMetadata(self.abakus.root, obj=metadataFile)

    def __write(self, metadata):
        logging.debug('Writing metadata for %s (%s)' % (metadata.getShortMetadataHash(), metadata.relPath))
        obj = metadata.getFileObject()
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
        logging.info('Creating snapshot of %d files' % len(metadataList.list()))

        obj = {}
        obj['type'] = 'Snapshot'
        obj['version'] = 1
        obj['timestamp'] = int(time.time())
        obj['metadataList'] = []

        hash = blake2b(digest_size=32)
        hash.update(bytes(str(obj['timestamp']), 'utf8'))

        for metadata in metadataList.list():
            self.abakus.metadataStore.add(metadata)
            hash.update(bytearray(metadata.metadataHash, 'utf8'))
            obj['metadataList'].append(metadata.metadataHash)

        obj['snapshotHash'] = hash.hexdigest()

        with open(os.path.join(self.snapshotDir, str(obj['timestamp'])), 'wb') as f:
            with io.StringIO() as stream:
                yaml.dump(obj, stream, default_flow_style=False, indent=2)
                f.write(zlib.compress(bytes(stream.getvalue(), 'utf8')))

        logging.info('Wrote snapshot %d' % obj['timestamp'])

    def latest(self):
        sortedList = sorted(os.listdir(self.snapshotDir), key=lambda x: int(x), reverse=True)
        if len(sortedList) == 0:
            return None
        logging.debug('Latest snapshot is %s' % sortedList[0])
        return self.__readSnapshot(sortedList[0])

    def __readSnapshot(self, timestamp):
        snapshotFilePath = os.path.join(self.snapshotDir, timestamp)
        with open(snapshotFilePath, 'rb') as f:
            snapshotFile = yaml.load(str(zlib.decompress(f.read()), 'utf8'))
            if snapshotFile['type'] != 'Snapshot':
                logging.error('Expected type Snapshot: %s' % snapshotFilePath)
                exit(1)
            if snapshotFile['version'] != 1:
                logging.error('Unknown Snapshot version %d: %s' % (snapshotFile['version'], snapshotFilePath))
                exit(1)

            list = AbakusFileMetadataList()
            for metadata in snapshotFile['metadataList']:
                list.add(self.abakus.metadataStore.load(metadata))

            return list
        return None


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
        latest = self.snapshotStore.latest()
        workdir = AbakusFileMetadataList(dir=self.root)
        diff = AbakusDiff(latest, workdir)
        print(diff)

    def cmd_snapshot(self):
        workdir = AbakusFileMetadataList(dir=self.root)
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
