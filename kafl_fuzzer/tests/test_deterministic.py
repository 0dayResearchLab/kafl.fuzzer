# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test kAFL deterministic mutations
"""

import random, struct 
from binascii import hexlify

from kafl_fuzzer.technique.interesting_values import *
from kafl_fuzzer.technique.arithmetic import *
from kafl_fuzzer.technique.bitflip import *
from kafl_fuzzer.technique.helper import *
from kafl_fuzzer.tests.helper import ham_distance

from kafl_fuzzer.common.util import IRP

helper_init()

def generate_irp_payloads(raw_payloads):
    """
    Generates a list of IRP instances from raw payloads.
    Accepts either a list of `bytes` or a list of `(bytes, ops)` tuples.
    Returns:
        irp_list: List of IRP instances
        ops_list: List of expected ops (None if not provided)
    """
    irp_list = []
    ops_list = []

    for item in raw_payloads:
        if isinstance(item, tuple) or isinstance(item, list):
            payload, ops = item
        else:
            payload, ops = item, None

        irp = IRP(
            IoControlCode=struct.pack('<L', 0x222004),
            InBuffer_length=struct.pack('<L', len(payload)),
            OutBuffer_length=struct.pack('<L', 0x2000),
            InBuffer=payload,
            Command=b"IOIO"
        )
        irp_list.append(irp)
        ops_list.append(ops)

    return irp_list, ops_list



def generate_effector_map(length):
    eff_map = []
    for i in range(length):
        eff_map.append(random.choice([True, False]))
    return eff_map


def run_mutation(func, payloads, v=False):

    global calls
    skip_zero = False
    eff_map = None

    def verifier(outdata, label=None):
        global calls
        calls += 1
        if v:
            print("Outdata: ",hexlify(outdata))

        return True, True

    for payload in payloads:
        calls = 0
        if v:
            print("Payload: ",hexlify(payload))

        func(bytearray(payload), verifier, effector_map=eff_map, skip_null=skip_zero)

        if v:
            print("Performed %d mutations." % calls)

def assert_invariants(func, max_flipped_bits, irp_list):
    """
    IRP-based function for verifying mutation invariants
    """
    for index, irp in enumerate(irp_list):
        payload = irp.InBuffer
        copy = bytearray(payload)  # Backup

        for skip_null in [False, True]:
            for use_eff_map in [False, True]:

                if use_eff_map:
                    eff_map = generate_effector_map(len(payload))
                else:
                    eff_map = None

                def verifier(modified_irp_list, label=None):
                    outdata = modified_irp_list[index].InBuffer
                    assert (
                        ham_distance(payload, outdata) <= max_flipped_bits
                    ), f"Flipped too many bits?\n{hexlify(payload)}\n{hexlify(outdata)}"
                    return True, True

                func(irp_list, index, verifier, effector_map=eff_map, skip_null=skip_null)

                # mutators may work directly on payload but must restore changes on exit!
                assert(irp.InBuffer == copy)

def assert_bitflip_invariants(func, flipped_bits, loops, skips, irp_list):
    """
    Verifies bitflip mutators using IRP structure.
    Ensures each mutation flips the expected number of bits, and the IRP input is restored.
    """

    eff_map_creator = mutate_seq_walking_byte

    for index in range(len(irp_list)):
        payload = irp_list[index].InBuffer
        copy = bytearray(payload)
        length = irp_list[index].InBuffer_length

        for skip_null in [False, True]:
            for use_eff_map in [False]:

                if use_eff_map:
                    eff_map = generate_effector_map(length)
                else:
                    eff_map = None

                calls = 0

                def verifier(_, label=None):
                    nonlocal calls
                    calls += 1
                    outdata = irp_list[index].InBuffer

                    # each mutator has characteristic max number of bits it can flip
                    # only special case is first call by eff_map_creator
                    if calls == 1 and use_eff_map and func == eff_map_creator:
                        assert ham_distance(payload, outdata) == 0
                    else:
                        dist = ham_distance(payload, outdata)
                        assert dist in [0, flipped_bits], \
                            "Bitflips mismatch on call %d:\n%s\n%s" % (
                                calls, hexlify(payload), hexlify(outdata))
                    # assert(bindiff(payload,outdata) in [b'\x80', b'\x40', b'\x20', b'\x10', b'\x08', b'\x04', b'\x02', b'\x01']), "Unexpected bitflip pattern"
                    return False, False

                func(irp_list, index, verifier, effector_map=eff_map, skip_null=skip_null)

                # mutators may work directly on payload but must restore changes on exit!
                assert(irp_list[index].InBuffer == copy)

                # number of bitflip calls is constant in standard case
                if not skip_null and not eff_map:
                    assert(calls == loops * length - skips)

def test_invariants(v=False):

    payloads = []
    for length in [range(0, 3), 16, 23, 33]:
        payloads.append(rand.bytes(32))

    irp_list, _ = generate_irp_payloads(payloads)

    func_calls = [
            [mutate_seq_8_bit_arithmetic, 8],
            [mutate_seq_16_bit_arithmetic, 16],
            [mutate_seq_32_bit_arithmetic, 20],
            [mutate_seq_8_bit_interesting, 8],
            [mutate_seq_16_bit_interesting, 16],
            [mutate_seq_32_bit_interesting, 32]]

    for func, max_bits in func_calls:
        assert_invariants(func, max_bits, irp_list)

    func_calls = [
                [mutate_seq_walking_byte, 8, 1, 0],
                [mutate_seq_two_walking_bytes, 16, 1, 1],
                [mutate_seq_four_walking_bytes, 32, 1, 3]]
    

    for func, bits, loops, skips in func_calls:
        assert_bitflip_invariants(func, bits, loops, skips, irp_list)

def assert_func_num_calls(func, irp_list, index, expected_calls):
    global calls
    calls = 0

    def execute(irp_list, label=None):
        global calls
        calls += 1

    func(irp_list, index, execute)

    assert(expected_calls == calls), "Expected %d, got %d calls for payload %s" % (expected_calls, calls, hexlify(payload))


def test_arith_8_call_num():

    func=mutate_seq_8_bit_arithmetic
    payloads = [
        bytes([0]),
        bytes([0, 0]),
        bytes([0, 0, 0]),
        bytes([0, 0, 0, 0]),
        bytes([255]),
        bytes([255, 255]),
        bytes([255, 255, 255]),
        bytes([128, 128]),
        bytes([30, 31]),
    ]

    irp_list, _ = generate_irp_payloads(payloads)

    for index in range(len(irp_list)):
        loops = irp_list[index].InBuffer_length
        ops = 2 * (AFL_ARITH_MAX - 1 - 6)
        expected_calls = loops * ops
        assert_func_num_calls(func, irp_list, index, expected_calls)


def test_arith_16_call_num():

    func=mutate_seq_16_bit_arithmetic
    payloads = [
            bytes([0]),
            bytes([0,0]),
            bytes([0,0,0]),
            bytes([0,0,0,0]),
            bytes([255]),
            bytes([255,255]),
            bytes([255,255,255])]

    irp_list, _ = generate_irp_payloads(payloads)

    for index in range(len(irp_list)):
        loops = irp_list[index].InBuffer_length -1
        ops = (AFL_ARITH_MAX-1)*2 # derived manually by review
        expected_calls = loops * ops
        assert_func_num_calls(func, irp_list, index, expected_calls)


def test_arith_32_call_num():

    func=mutate_seq_32_bit_arithmetic

    payloads = [
            bytes([0]),
            bytes([0,0]),
            bytes([0,0,0]),
            bytes([0,0,0,0]),
            bytes([0,0,0,0,0]),
            bytes([0,0,0,0,0,0]),
            bytes([255]),
            bytes([255,255]),
            bytes([255,255,255]),
            bytes([255,255,255,255]),
            bytes([255,255,255,255,255])]

    irp_list, _ = generate_irp_payloads(payloads)

    for index in range(len(irp_list)):
        if irp_list[index].InBuffer_length < 3:
            loops = 0
        else:
            loops = irp_list[index].InBuffer_length-3
        ops = (AFL_ARITH_MAX-1)*2 # derived manually by review
        expected_calls = loops * ops
        assert_func_num_calls(func, irp_list, index, expected_calls)

def test_int_8_call_num():

    func=mutate_seq_8_bit_interesting

    payloads = [
            [bytes([0]), 2],
            [bytes([0,0]), 2],
            [bytes([0,0,0]), 2],
            [bytes([0,0,0,0]), 2],
            [bytes([255]), 3],
            [bytes([255,255]), 3],
            [bytes([255,255,255]), 3],
            [bytes([128,128]), 4],
            [bytes([32,32]), 3]]

    irp_list, ops_list = generate_irp_payloads(payloads)

    for index in range(len(irp_list)):
        loops = irp_list[index].InBuffer_length
        expected_calls = loops * ops_list[index]
        assert_func_num_calls(func, irp_list, index, expected_calls)

def test_int_16_call_num():

    func=mutate_seq_16_bit_interesting

    payloads = [
            [bytes([0]), 0],
            [bytes([0,0]), 6],
            [bytes([0,0,0]), 6],
            [bytes([0,0,0,0]), 6],
            [bytes([255]), 0],
            [bytes([255,255]), 10],
            [bytes([255,255,255]), 10],
            [bytes([255,128]), 22],
            [bytes([255,128,128]), 23],
            [bytes([128,128]), 24],
            [bytes([32,32]), 26]]

    irp_list, ops_list = generate_irp_payloads(payloads)

    for index in range(len(irp_list)):
        loops = irp_list[index].InBuffer_length-1
        expected_calls = loops * ops_list[index]
        assert_func_num_calls(func, irp_list, index, expected_calls)

def test_int_32_call_num():

    func=mutate_seq_32_bit_interesting

    payloads = [
            [bytes([0]), 0],
            [bytes([0,0]), 0],
            [bytes([0,0,0]), 0],
            [bytes([0,0,0,0]), 10],
            [bytes([255]), 0],
            [bytes([255,255]), 0],
            [bytes([255,255,255,255]), 26],
            [bytes([255,128]), 22],
            [bytes([255,128,128]), 23],
            [bytes([255,255,128,128]), 38],
            [bytes([128,128,128,128,128]), 44]]

    irp_list, ops_list = generate_irp_payloads(payloads)

    for index in range(len(irp_list)):
        if irp_list[index].InBuffer_length < 3:
            loops = 0
        else:
            loops = irp_list[index].InBuffer_length-3

        expected_calls = loops * ops_list[index]
        assert_func_num_calls(func, irp_list, index, expected_calls)



import timeit
def deter_benchmark():

    payloads = [b'abcdefghijklmnopqrstuvwxyz01234567890', bytes([254,255,255,254,255,254,252])]

    def bench_arith_8():
        run_mutation(mutate_seq_8_bit_arithmetic, payloads)

    def bench_arith_16():
        run_mutation(mutate_seq_16_bit_arithmetic, payloads)

    def bench_arith_32():
        run_mutation(mutate_seq_32_bit_arithmetic, payloads)

    def bench_int32():
        run_mutation(mutate_seq_32_bit_interesting, payloads)

    def bench_int16():
        run_mutation(mutate_seq_16_bit_interesting, payloads)

    def bench_int8():
        run_mutation(mutate_seq_8_bit_interesting, payloads)

    def bench_flip_bits():
        run_mutation(mutate_seq_walking_bits, payloads)
        run_mutation(mutate_seq_two_walking_bits, payloads)
        run_mutation(mutate_seq_four_walking_bits, payloads)

    def bench_walk_bytes():
        run_mutation(mutate_seq_walking_byte, payloads)
        run_mutation(mutate_seq_two_walking_bytes, payloads)
        run_mutation(mutate_seq_four_walking_bytes, payloads)

    num = 5000

    time_flips = timeit.timeit(stmt=bench_flip_bits, number=num*3)
    print("afl_flip_1/2/4 = %5.02fs" % time_flips)

    time_walks = timeit.timeit(stmt=bench_walk_bytes, number=num*3)
    print("afl_walk_1/2/4 = %5.02fs" % time_walks)

    time_arith8 = timeit.timeit(stmt=bench_arith_8, number=num)
    print("afl_arith_8  = %5.02fs" % time_arith8)

    time_arith16 = timeit.timeit(stmt=bench_arith_16, number=num)
    print("afl_arith_16 = %5.02fs" % time_arith16)

    time_arith32 = timeit.timeit(stmt=bench_arith_32, number=num)
    print("afl_arith_32 = %5.02fs" % time_arith32)

    time_int8 = timeit.timeit(stmt=bench_int8, number=num)
    print("afl_int_8 = %5.02fs" % time_int8)

    time_int16 = timeit.timeit(stmt=bench_int16, number=num//2)
    print("afl_int_16 = %5.02fs" % time_int16)

    time_int32 = timeit.timeit(stmt=bench_int32, number=num//2)
    print("afl_int_32 = %5.02fs" % time_int32)

def deter_main():

    deter_benchmark()
    return

    # payloads = [b'\x00', b'abcdefghijk', bytes([0,1,2,3,4,5,6,7,8,9]), bytes([254,255,255,254,255,254,252])]
    #payloads = [b'abcdefghijk']
    #payloads = [b'\x00\x00']


    #run_mutation(mutate_seq_8_bit_arithmetic_array, payloads,v=verbose)
    #run_mutation(mutate_seq_8_bit_arithmetic, payloads,v=verbose)
    #run_mutation(mutate_seq_16_bit_arithmetic_array, payloads,v=verbose)
    #run_mutation(mutate_seq_16_bit_arithmetic, payloads,v=verbose)
    #run_mutation(mutate_seq_32_bit_arithmetic_array, payloads,v=verbose)
    #run_mutation(mutate_seq_32_bit_arithmetic, payloads,v=verbose)

    #run_mutation(mutate_seq_8_bit_interesting_array, payloads,v=verbose)
    #run_mutation(mutate_seq_8_bit_interesting, payloads,v=verbose)
    #run_mutation(mutate_seq_16_bit_interesting, payloads, v=verbose)
    #run_mutation(mutate_seq_16_bit_interesting, payloads, v=verbose)
    #run_mutation(mutate_seq_32_bit_interesting, payloads, v=verbose)
    #run_mutation(mutate_seq_32_bit_interesting, payloads, v=verbose)

    #test_invariables()
    #test_arith_8_calls()
    #test_arith_16_calls()
    #test_arith_32_calls()
    #test_int_8_calls()
    test_int_16_calls()
    test_int_32_calls()