# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test kAFL havoc mutations
"""

import struct
from binascii import hexlify

from kafl_fuzzer.technique.havoc_handler import *
from kafl_fuzzer.technique.helper import *
from kafl_fuzzer.tests.helper import ham_distance
from kafl_fuzzer.common.util import IRP

EMPTY_DICT = {}
ITERATIONS = 2 * 1024

helper_init()

def generate_irp_input(data: bytes) -> IRP:
    return IRP(
        IoControlCode=struct.pack('<L', 0x222004),
        InBuffer_length=struct.pack('<L', len(data)),
        OutBuffer_length=struct.pack('<L', 0x2000),
        InBuffer=data,
        Command=b"IOIO"
    )

def test_redqueen_dict_clear():
    clear_redqueen_dict()
    assert EMPTY_DICT == get_redqueen_dict(), "Failed to clear RQ dict!"

def test_redqueen_dict_add():
    MY_DICT = {23: b'ABCD', 42: b'1234'}
    clear_redqueen_dict()

    for addr in MY_DICT:
        add_to_redqueen_dict(addr, MY_DICT[addr])

    add_to_redqueen_dict(23, MY_DICT[23])  # dupes should be dropped

    rq_dict = get_redqueen_dict()
    for addr in MY_DICT:
        assert MY_DICT[addr] in rq_dict[addr], "Mismatching elements in RQ dict!"

def verify_havoc(func, expected_bits=1, min_len=1):
    db = [b'1', b'123134', b'adfakh\0adfkn\x23']
    for _ in range(ITERATIONS):
        assert func(b'') == b''
        for data_in in db:
            if len(data_in) < min_len:
                continue
            irp = generate_irp_input(data_in)
            mutated = func(irp.InBuffer)
            assert len(data_in) == len(mutated), "Returned length mismatch!"
            dist = ham_distance(data_in, mutated)
            assert dist <= expected_bits, f"Too many bits flipped! ({dist} > {expected_bits})"

def test_havoc_bit_flip():
    verify_havoc(havoc_perform_bit_flip, expected_bits=1)

def test_havoc_interesting_value_8():
    for _ in range(ITERATIONS):
        assert havoc_perform_insert_interesting_value_8(b'') == b''
        db = [b'1', b'123134', b'adfakh\0adfkn\x23']
        for data_in in db:
            irp = generate_irp_input(data_in)
            out = havoc_perform_insert_interesting_value_8(irp.InBuffer)
            assert len(data_in) == len(out), "Returned length mismatch!"
            assert ham_distance(data_in, out) <= 8, "Too many bits flipped!"
            assert any(struct.pack("!b", i) in out for i in interesting_8_Bit), "Interesting value not inserted!"

def test_havoc_interesting_value_16():
    for _ in range(ITERATIONS):
        assert havoc_perform_insert_interesting_value_16(b'') == b''
        assert havoc_perform_insert_interesting_value_16(b'\x23') == b'\x23'
        db = [b'42', b'123134', b'adfakh\0adfkn\x23']
        for data_in in db:
            irp = generate_irp_input(data_in)
            out = havoc_perform_insert_interesting_value_16(irp.InBuffer)
            assert len(out) == len(data_in)
            assert ham_distance(data_in, out) <= 16
            assert any(
                struct.pack("<h", i) in out or struct.pack(">h", i) in out
                for i in interesting_16_Bit
            ), "Interesting 16-bit value not inserted!"

def test_havoc_interesting_value_32():
    for _ in range(ITERATIONS):
        assert havoc_perform_insert_interesting_value_32(b'') == b''
        assert havoc_perform_insert_interesting_value_32(b'\x23') == b'\x23'
        assert havoc_perform_insert_interesting_value_32(b'\x23ab') == b'\x23ab'
        db = [b'42ab', b'123134acd', b'adf23akh\0adfkn\x23', b'!#@$%^&*']
        for data_in in db:
            irp = generate_irp_input(data_in)
            out = havoc_perform_insert_interesting_value_32(irp.InBuffer)
            assert len(out) == len(data_in)
            assert ham_distance(data_in, out) <= 32
            assert any(
                struct.pack("<i", i) in out or struct.pack(">i", i) in out
                for i in interesting_32_Bit
            ), "Interesting 32-bit value not inserted!"

def test_havoc_insert_line(v=False):
    db = [b'42ab', b'123134acd', b'adf23akh\0adfkn\x23', b'!#@$%^&*']
    for data_in in db:
        irp = generate_irp_input(data_in)
        out = havoc_insert_line(irp.InBuffer)
        if v:
            print("In :", hexlify(data_in))
            print("Out:", hexlify(out))

def havoc_main():
    test_redqueen_dict_clear()
    test_redqueen_dict_add()
    test_havoc_bit_flip()
    test_havoc_interesting_value_8()
    test_havoc_interesting_value_16()
    test_havoc_interesting_value_32()
    test_havoc_insert_line(v=True)
    print("All havoc tests passed!")
