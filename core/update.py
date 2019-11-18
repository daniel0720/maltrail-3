#!/usr/bin/env python3

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import csv
import glob
import inspect
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib2

sys.dont_write_bytecode = True
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))) # to enable calling from current directory too


from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import make_mask
from core.common import bogon_ip
from core.common import cdn_ip
from core.common import check_whitelisted
from core.common import load_trails
from core.common import retrieve_content
from core.settings import config
from core.settings import read_config
from core.settings import read_whitelist
from core.settings import BAD_TRAIL_PREFIXES
from core.settings import FRESH_IPCAT_DELTA_DAYS
from core.settings import LOW_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_REFERENCES
from core.settings import IPCAT_CSV_FILE
from core.settings import IPCAT_SQLITE_FILE
from core.settings import IPCAT_URL
from core.settings import ROOT_DIR
from core.settings import TRAILS_FILE
from core.settings import USERS_DIR

# patch for self-signed certificates (e.g. CUSTOM_TRAILS_URL)
try:
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context
except (ImportError, AttributeError):
    pass

# 在非windows系统中，改变filepath的文件属主
def _chown(filepath):
    if not subprocess._mswindows and os.path.exists(filepath):
        try:
            os.chown(filepath, int(os.environ.get("SUDO_UID", -1)), int(os.environ.get("SUDO_GID", -1)))
        except Exception as ex:
            print("[!] chown problem with {} ({})".format(filepath, ex))

def _fopen(filepath, mode='rb'):
    retval = open(filepath, mode)
    if "w+" in mode:
        _chown(filepath)
    return retval

def update_trails(force=False, offline=False):
    """
    Update trails from feeds
    """

    success = False
    trails = {}
    duplicates = {}

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0755)
    except Exception as ex:
        exit("[!] something went wrong during creation of directory '{}' ({})".format(USERS_DIR, ex))
    
    _chown(USERS_DIR)

    if config.UPDATE_SERVER:    # 如果配置了trails更新服务器，则从服务器读取trails并写入到TRAILS_FILE文件
        print("[i] retrieving trails from provided 'UPDATE_SERVER' server...")
        content = retrieve_content(config.UPDATE_SERVER)
        if not content or content.count(',') < 2:
            print("[x] unable to retrieve data from {}".format(config.UPDATE_SERVER))
        else:
            with _fopen(TRAILS_FILE, 'w+b') as f:
                f.write(content)
            trails = load_trails()

    else:
        trail_files = set()     # 存放trails文件夹下的trails文件路径和名称
        for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, "trails"))):
            for filename in filenames:
                trail_files.add(os.path.abspath(os.path.join(dirpath, filename)))
        
        if config.CUSTOM_TRAILS_DIR:
            for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, os.path.expanduser(config.CUSTOM_TRAILS_DIR)))) :
                for filename in filenames:
                    trail_files.add(os.path.abspath(os.path.join(dirpath, filename)))

        if not trails and (force or not os.path.isfile(TRAILS_FILE) or (time.time() - os.stat(TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD or os.stat(TRAILS_FILE).st_size == 0 or any(os.stat(_).st_mtime > os.stat(TRAILS_FILE).st_mtime for _ in trail_files)):
            if not config.no_updates:
                print("[i] updating trails (this might take a while)...")
            else:
                print("[i] checking trails...")

            # 将trails目录下的所有文件名都加入到filenames列表中
            if not offline and (force or config.USE_FEED_UPDATES):
                _ = os.path.abspath(os.path.join(ROOT_DIR, "trails", "feeds"))
                if _ not in sys.path:
                    sys.path.append(_)

                filenames = sorted(glob.glob(os.path.join(_, "*.py")))  # glob模块查找符合特定规则的文件路径名，本例子中查找文件夹下的.py文件，返回文件路径列表
            else:
                filenames = []

            _ = os.path.abspath(os.path.join(ROOT_DIR, "trails"))
            if _ not in sys.path:
                sys.path.append(_)
            
            filenames += [os.path.join(_, "static")]
            filenames += [os.path.join(_, "custom")]

            filenames += [_ for _ in filenames if "__init__.py" not in _]

            if config.DISABLED_FEEDS:
                filenames = [filename for filename in filenames if os.path.splitext(os.path.split(filename)[-1])[0] not in re.split(r"[^\w]+", config.DISABLED_FEEDS)]

            # 处理每个trail文件
            for i in range(len(filenames)):
                filename = filenames[i]

                # 导入.py文件
                try:
                    module = __import__(os.path.basename(filename).split(".py")[0])
                except (ImportError, SyntaxError) as ex:
                    print("[x] something went wrong during import of feed file '{}' ({})".format(filename, ex))
                    continue

                for name, function in inspect.getmembers(module, inspect.isfunction):
                    if name == 'fetch':
                        print(" [o] '{}'{}".format(module.__url__, " " * 20 if len(module.__url__) < 20 else ""))
                        sys.stdout.write("[?] progress: %d/%d (%d%%)\r" % (i, len(filenames), i * 100 / len(filenames)))
                        sys.stdout.flush()

                        if config.DISABLED_TRAILS_INFO_REGEX and re.search(config.DISABLED_TRAILS_INFO_REGEX, getattr(module, "__info__", "")):
                            continue

                        try:
                            results = function()
                            for item in results.items():
                                if item[0].startswith("www.") and '/' not in item[0]:
                                    item = [item[0][len("www."):], item[1]]
                                if item[0] in trails:
                                    if item[0] not in duplicates:
                                        duplicates[item[0]] = set((trails[item[0]][1],))
                                    duplicates[item[0]].add(item[1][1])
                                if not (item[0] in trails and (any(_ in item[1][0] for _ in LOW_PRIORITY_INFO_KEYWORDS) or trails[item[0]][1] in HIGH_PRIORITY_REFERENCES)) or (item[1][1] in HIGH_PRIORITY_REFERENCES and "history" not in item[1][0]) or any(_ in item[1][0] for _ in HIGH_PRIORITY_INFO_KEYWORDS):
                                    trails[item[0]] = item[1]
                            if not results and "abuse.ch" not in module.__url__:
                                print("[x] something went wrong during remote data retrieval ('{}')".format(module.__url__))
                        except Exception as ex:
                            print("[x] something went wrong during processing of feed file '{}' ('{}')".format(filename, ex))
                
                try:
                    sys.modules.pop(module.__name__)
                    del module
                except Exception:
                    pass
            
            # custom trails from remote location
            