#!/usr/bin/env python3

import logging
import os
import zlib


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

