#!/usr/bin/env python3

import io


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
