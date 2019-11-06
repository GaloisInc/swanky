#!/usr/bin/env python3
import json
import sys
import subprocess

assert len(
    sys.argv) == 2, "usage: etc/test_workspace.py 'feature_one feature_two'"

FEATURES = set(sys.argv[1].split())

metadata = json.loads(
    subprocess.check_output(
        ['cargo', 'metadata', '--no-deps', '--format-version', '1']))

for name in (entry.split()[0] for entry in metadata['workspace_members']):
    for pkg in metadata['packages']:
        if pkg['name'] == name:
            break
    else:
        raise Exception("Package %r cannot be found" % name)
    subprocess.check_call([
        'cargo',
        'build',
        '-Z',
        'package-features',
        '-p',
        name,
        '--verbose',
        '--examples',
        '--tests',
        '--benches',
        '--features',
        ' '.join(set(pkg["features"]) & FEATURES),
    ])
    subprocess.check_call([
        'cargo',
        'test',
        '-Z',
        'package-features',
        '-p',
        name,
        '--verbose',
        '--features',
        ' '.join(set(pkg["features"]) & FEATURES),
    ])
