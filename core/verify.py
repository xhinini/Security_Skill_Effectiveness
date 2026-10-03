#!/usr/bin/env python3
"""Verify exported ZIP members against their recorded SHA-256 checksums."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archives', nargs='+', type=Path)
    args = p.parse_args()
    for path in args.archives:
        with zipfile.ZipFile(path) as z:
            index = json.loads(z.read('FILE_INDEX.json'))
            names = z.namelist()
            assert len(names) == len(set(names)), f'duplicate members: {path}'
            assert set(names) == {r['path'] for r in index} | {'FILE_INDEX.json'}
            for row in index:
                name = PurePosixPath(row['path'])
                assert not name.is_absolute() and '..' not in name.parts
                with z.open(row['path']) as f:
                    h = hashlib.sha256()
                    size = 0
                    for block in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(block)
                        size += len(block)
                assert size == row['bytes'] and h.hexdigest() == row['sha256'], row['path']
            print(f'PASS {path.name}: {len(index)} verified files', flush=True)


if __name__ == '__main__':
    main()
