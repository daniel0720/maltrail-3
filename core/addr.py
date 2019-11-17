#!/usr/bin/env python3

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
# 提供了操作IP地址的一些方法，例如IP地址转换成整数，整数转换成IP地址、压缩IPv6地址、设置掩码等
# 自己实现一些方法，减少对第三方库的依赖

import re
import ipaddress

def addr_to_int(value):
    _ = value.split('.')
    return (int(_[0]) << 24) + (int(_[1]) << 16) + (int(_[2]) << 8) + int(_[3])

def int_to_addr(value):
    return '.'.join(str(value >> n & 0xff) for n in (24, 16, 8, 0))

def make_mask(bits):
    return 0xffffffff ^ (1 << 32 - bits) - 1

def compress_ipv6(address):
    zeros = re.findall("(?:0000:)+", address)
    if zeros:
        address = address.replace(sorted(zeros, key=lambda _: len(_))[-1], ":", 1)
        address = re.sub(r"(\A|:)0+(\w)", "\g<1>\g<2>", address)
        if address == ":1":
            address = "::1"
    return address


def inet_ntoa6(packet_ip):
    _ = packet_ip.encode("hex")
    return compress_ipv6(":".join(_[i:i + 4] for i in range(0, len(_), 4)))

if __name__ == '__main__':
    print(addr_to_int('192.168.131.1'))
    print(int(ipaddress.ip_address('192.168.131.1')))
    print(ipaddress.ip_address(3232269057))
    print("%x" % make_mask(16))
    print(compress_ipv6('2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b'))
    addr6 = ipaddress.IPv6Address('2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b')
    print(addr6.compressed)
    