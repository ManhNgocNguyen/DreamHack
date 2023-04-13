import math
from pwn import *
import gmpy2
import os
from gmpy2 import iroot
from Crypto.Util.number import *
from sympy.ntheory.modular import crt
from fractions import Fraction

p = remote("host3.dreamhack.games", 9801)
# context.log_level= 0

key_set = set(list(range(255)))
rand_set = set(list(range(256)))
my_key = list(rand_set - key_set)[0]

p.sendlineafter(b'>> ', '3')
p.sendlineafter(b'>> ', '255')
p.recvuntil(b': ')
flag_len = len(p.recvline()) // 2

flag_set = [list(range(256)) for _ in range(flag_len)]
flag = [' ' for _ in range(flag_len)]

count = 0
while sum([len(i) for i in flag_set]) > flag_len:
    p.sendlineafter(b'>> ', '3')
    p.sendlineafter(b'>> ', '255')
    p.recvuntil(b': ')
    enc = bytes.fromhex(p.recvline().strip().decode())

    for i in range(flag_len):
        if flag_set[i].count(enc[i]) == 1:
            flag_set[i].pop(flag_set[i].index(enc[i]))
        if len(flag_set[i]) == 1:
            flag[i] = chr(flag_set[i][-1] ^ my_key)
    print(''.join(flag))
    print(' '.join([str(len(i)) for i in flag_set]))
    count += 1

print(count)
print(''.join(flag))