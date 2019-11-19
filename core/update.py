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
    trails = {}             # 存放trail字典，key是trail，value是__info__和__reference__
    duplicates = {}

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0755)
    except Exception as ex:
        exit("[!] something went wrong during creation of directory '{}' ({})".format(USERS_DIR, ex))
    
    _chown(USERS_DIR)

    # 如果配置了trails更新服务器，就从更新服务器获取trail
    if config.UPDATE_SERVER:    # 如果配置了trails更新服务器，则从服务器读取trails并写入到TRAILS_FILE文件
        print("[i] retrieving trails from provided 'UPDATE_SERVER' server...")
        content = retrieve_content(config.UPDATE_SERVER)
        if not content or content.count(',') < 2:
            print("[x] unable to retrieve data from {}".format(config.UPDATE_SERVER))
        else:
            with _fopen(TRAILS_FILE, 'w+b') as f:
                f.write(content)
            trails = load_trails()

    # 没有配置trails更新服务器，就从当前文件中读取trails
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
            if config.CUSTOM_TRAILS_URL:
                print(" [o] '(remote custom)'{}".format(" " * 20))
                for url in re.split(r"[;,]", config.CUSTOM_TRAILS_URL):
                    url = url.strip()
                    if not url:
                        continue

                    url = ("http://{}".format(url)) if not "//" in url else url
                    content = retrieve_content(url)

                    if not content:
                        print("[x] unable to retrieve data (or empty response) from '{}'".format(url))
                    else:
                        __info__ = "blacklisted"
                        __reference__ = "(remote custom)"   # urlparse.urlsplit(url).netloc
                        for line in content.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('#'):        # #开始的行是注释行，跳过注释行和空行
                                continue
                            line = re.sub(r"\s*#.*", "", line)          # 去掉行中的注释部分
                            if '://' in line:                           # 此行为域名，取域名部分
                                line = re.search(r"://(.*)", line).group(1)
                            line = line.rstrip('/')

                            if line in trails and any(_ in trails[line][1] for _ in ("custom", "static")):      # 在trails中已经有了本条目，调到下一条循环
                                continue

                            if '/' in line:                             # 取域名部分或者IP网络号
                                trails[line] = (__info__, __reference__)
                                line = line.split('/')[0]
                            elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):    # line为IP
                                trails[line] = (__info__, __reference__)
                            else:
                                trails[line.strip('.')] = (__info__, __reference__)
                        
                        for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", content):
                            prefix, mask = match.groups()
                            mask = int(mask)
                            if mask > 32:
                                continue
                            start_int = addr_to_int(prefix) & make_mask(mask)
                            end_int = start_int | ((1 << 32 - mask) - 1)
                            if 0 <= end_int - start_int <= 1024:
                                address = start_int
                                while start_int <= address <= end_int:
                                    trails[int_to_addr(address)] = (__info__, __reference__)
                                    address += 1
                        
            # basic cleanup
            for key in trails.keys():
                if key not in trails:
                    continue
                if config.DISABLED_TRAILS_INFO_REGEX:
                    if re.search(config.DISABLED_TRAILS_INFO_REGEX, trails[key][0]):
                        del trails[key]
                        continue
                
                try:
                    _key = key.decode("utf8").encode("idna")
                    if _key != key:
                        trails[_key] = trails[key]
                        del trails[key]
                        key = _key
                except:
                    pass

