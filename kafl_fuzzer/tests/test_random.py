# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test kAFL rand() wrapper / coin toss
"""

import struct
import timeit
import random

from kafl_fuzzer.technique.helper import rand
from kafl_fuzzer.common.util import IRP

ITERATIONS = 5000

def generate_irp_input(data: bytes) -> IRP:
    return IRP(
        IoControlCode=struct.pack('<L', 0x222004),
        InBuffer_length=struct.pack('<L', len(data)),
        OutBuffer_length=struct.pack('<L', 0x2000),
        InBuffer=data,
        Command=b"IOIO"
    )

def get_int_bitmap(limit, samples):
    elements = limit
    bitmap = [0 for _ in range(elements)]
    for _ in range(samples * elements):
        val = rand.int(limit)
        bitmap[val] += 1
    return bitmap

def test_rand_int():
    limits = [1, 2, 4, 7, 13, 17, 20, 32, 50, 100]
    samples = 5000
    for limit in limits:
        bitmap = get_int_bitmap(limit, samples)
        assert(bitmap[0] != 0), "rand.int() not spanning complete range?"
        assert(bitmap[-1] != 0), "rand.int() not spanning complete range?"
        for idx in range(len(bitmap)):
            bias = abs(1 - bitmap[idx] / samples)
            assert(bias < 0.05), f"rand.int() detected bias at bitmap[{idx}]={bias} - need more samples?"

def get_select_bitmap(elements, samples):
    array = [x for x in range(elements)]
    bitmap = [0 for _ in range(elements)]
    for _ in range(samples * elements):
        val = rand.select(array)
        bitmap[val] += 1
    return bitmap

def get_gauss_sum(array, samples):
    expect = 0.5 * array[-1] * (array[-1] + 1)
    count = 0
    for _ in range(samples * len(array)):
        count += rand.select(array)
    real = count / samples
    return expect, real

def test_rand_select():
    samples = 5000
    elements = [1, 2, 17, 64]
    for element in elements:
        bitmap = get_select_bitmap(element, samples)
        assert(bitmap[0] != 0), "rand.select() not spanning complete range?"
        assert(bitmap[-1] != 0), "rand.select() not spanning complete range?"
        for idx in range(len(bitmap)):
            bias = abs(1 - bitmap[idx] / samples)
            assert(bias < 0.1), f"rand.select() detected bias at bitmap[{idx}]={bias} - need more samples?"
    for limit in elements:
        array = [i for i in range(limit)]
        expect, real = get_gauss_sum(array, samples)
        assert(abs(expect - real) / 100 < 0.1), f"Gauss Sum mismatch: {expect} != {real}"

def get_bytes_bitmap(length, samples):
    elements = 256
    bitmap = [0 for _ in range(elements)]
    for _ in range(samples):
        irp = generate_irp_input(rand.bytes(length))
        for byte in irp.InBuffer:
            bitmap[byte] += 1
    return bitmap

def test_rand_bytes():
    lengths = [1, 3, 32, 17, 64]
    for length in lengths:
        bitmap = get_bytes_bitmap(length, 1)
        total = sum(bitmap)
        assert(total == length), "rand.bytes() returned unexpected length"
    length = 256
    samples = 100
    byte_array = list(rand.bytes(length))
    _, real = get_gauss_sum(byte_array, samples)
    expect = 255 / 2 * (255 + 1)
    assert(abs(real / samples / expect) < 0.1), f"rand.bytes() bias detected, gauss count: {real/samples} != {expect}"

def test_coin_semantics():
    samples = 1000
    check = sum(1 for _ in range(samples) if rand.int(2) == 0)
    assert(abs(check / samples - 0.5) < 0.1), "Coin toss bias - semantics mismatch?"
    check = sum(1 for _ in range(samples) if rand.int(4) == 0)
    assert(abs(check / samples - 0.25) < 0.1), "Coin toss bias - semantics mismatch?"
    check = sum(1 for _ in range(samples) if rand.int(100) < 20)
    assert(abs(check / samples - 0.2) < 0.1), "Coin toss bias - semantics mismatch?"
    check = 0
    for _ in range(samples):
        if rand.int(2) == 0:
            if rand.int(4) != 0:
                check += 1  # 3/4 * 1/2
    assert(abs(check / samples - 0.375) < 0.1), "Coin toss bias - semantics mismatch?"

def bench_randint():
    data = bytearray(rand.int(256) for _ in range(2048))
    selection = bytearray(rand.select(data) for _ in range(256))
    assert len(selection) == 256

def bench_randomint():
    data = bytearray(random.randint(0, 255) for _ in range(2048))
    selection = bytearray(random.choice(data) for _ in range(256))
    assert len(selection) == 256

def rand_benchmark():
    time_rand = timeit.timeit(stmt=bench_randint, number=1000)
    print("bench_rand.int() = %5.02fs" % time_rand)
    time_random = timeit.timeit(stmt=bench_randomint, number=1000)
    print("bench_random.int() = %5.02fs" % time_random)

def rand_main():
    test_rand_int()
    test_rand_select()
    test_rand_bytes()
    test_coin_semantics()
    rand_benchmark()