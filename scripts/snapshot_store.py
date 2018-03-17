#!/usr/bin/env python3

import datetime
import logging
import os

from pyblake2 import blake2b
import yaml


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

            list = AbakusMetadataList()
            for metadata in snapshotFile['metadataList']:
                list.add(self.abakus.metadataStore.load(metadata))

            return list
        return None
