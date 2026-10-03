"""Build a stdlib-only node zipapp; requires Python 3.12+ at runtime."""
import argparse
from pathlib import Path
import shutil
import tempfile
import zipapp
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('output',type=Path)
args=parser.parse_args()
if args.output.exists(): parser.error('Output already exists; choose a new filename')
with tempfile.TemporaryDirectory(prefix='signalhound-node-build-') as directory:
    shutil.copytree(Path(__file__).resolve().parents[1]/'backend'/'signalhound_node',Path(directory)/'signalhound_node',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    zipapp.create_archive(directory,target=args.output,interpreter='/usr/bin/env python3',main='signalhound_node.client:main')
print(f'Built {args.output}; no third-party client dependencies.')
