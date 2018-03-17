#!/usr/bin/env python3

import logging
import os
import zlib

import yaml


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
            return AbakusMetadata(self.abakus.root, obj=metadataFile)

    def __write(self, metadata):
        logging.debug('Writing metadata for %s (%s)' % (metadata.getShortMetadataHash(), metadata.relPath))
        obj = metadata.getFileObject()
        with open(os.path.join(self.metadataDir, metadata.metadataHash), 'wb') as f:
            with io.StringIO() as stream:
                yaml.dump(obj, stream, default_flow_style=False, indent=2)
                f.write(zlib.compress(bytes(stream.getvalue(), 'utf8')))

        return True

