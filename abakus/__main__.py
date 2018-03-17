#!/usr/bin/env python3

import argparse
import logging
import os
import sys

import yaml

from blob import AbakusBlobStore
from metadata import AbakusMetadata, AbakusMetadataList, AbakusMetadataStore, AbakusDiff
from snapshot import AbakusSnapshotStore


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

        #with open(os.path.join(self.homeDir, 'config'), 'r') as f:
        #    config = yaml.load(f)

    def cmd_status(self):
        latest = self.snapshotStore.latest()
        workdir = AbakusMetadataList(dir=self.root)
        diff = AbakusDiff(latest, workdir)
        print(diff)

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
