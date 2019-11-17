#!/usr/bin/env python3

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sys

PYVERSION = sys.version.split()[0]

if PYVERSION < '3':
    exit("[CRITICAL] incompatible Python version detected ({}). For successfully running Maltrail you'll have to use version 3.0 or higher (visit 'http://www.python.org/download/')".format(PYVERSION)) 