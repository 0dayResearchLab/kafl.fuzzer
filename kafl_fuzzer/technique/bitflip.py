# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style bitflip mutations (deterministic stage).
"""

from kafl_fuzzer.common.util import MAX_WALKING_BITS_SIZE

def mutate_seq_walking_bits(irp_list, index, func, skip_null=False, effector_map=None):
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length



    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_WALKING_BITS_SIZE:
        end = MAX_WALKING_BITS_SIZE

    for i in range(start, end):
        orig = data[i]
        for j in range(8):
            data[i] ^= 0x80 >> j
            func(irp_list, label="afl_flip_1/1")
            data[i] = orig


def mutate_seq_two_walking_bits(irp_list, index, func, skip_null=False, effector_map=None):
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_WALKING_BITS_SIZE:
        end = MAX_WALKING_BITS_SIZE


    for i in range(start, end  - 1):

        if effector_map:
            if effector_map[i:i+2] == bytes(2):
                continue

        if skip_null and data[i:i+2] == bytes(2):
            continue
        
        orig = data[i:i+2]

        for j in range(7):
            data[i] ^= (0xc0 >> j)
            #data[i] ^= (0x80 >> j + 1)
            func(irp_list, label="afl_flip_2/1")
            data[i] = orig[0]

        # j=7
        data[i]   ^= (0x80 >> 7)
        data[i+1] ^= (0x80 >> 0)
        func(irp_list, label="afl_flip_2/1")
        data[i:i+2] = orig

    # special round for last byte
    i=len(data)-1
    orig = data[i]

    # if effector_map and not effector_map[i]:
    #     return
    # if skip_null and not data[i]:
    #     return

    for j in range(7):
        data[i] ^= (0xc0 >> j)
        #data[i] ^= (0x80 >> j + 1)
        func(irp_list, label="afl_flip_2/1")
        data[i] = orig


def mutate_seq_four_walking_bits(irp_list, index, func, skip_null=False, effector_map=None):
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_WALKING_BITS_SIZE:
        end = MAX_WALKING_BITS_SIZE


    for i in range(start, end -1):

        orig = data[i:i+2]

        for j in range(5):
            data[i] ^= (0xf0 >> j)
            func(irp_list, label="afl_flip_2/1")
            data[i] = orig[0]

        # j=5,6,7
        data[i]   ^= (0xe0 >> 5)
        data[i+1] ^= (0x80 >> 0)
        func(irp_list, label="afl_flip_2/1")
        data[i:i+2] = orig
        
        data[i]   ^= (0xc0 >> 6)
        data[i+1] ^= (0xc0 >> 0)
        func(irp_list, label="afl_flip_2/1")
        data[i:i+2] = orig
        
        data[i]   ^= (0x80 >> 7)
        data[i+1] ^= (0xe0 >> 0)
        func(irp_list, label="afl_flip_2/1")
        data[i:i+2] = orig

    # special round for last byte
    i=len(data)-1
    orig = data[i]

    # if effector_map and not effector_map[i]:
    #     return
    # if skip_null and not data[i]:
    #     return

    for j in range(5):
        # j=0,1,2,3,4
        data[i] ^= (0xf0 >> j)
        func(irp_list, label="afl_flip_2/1")
        data[i] = orig


def mutate_seq_walking_byte(irp_list, index, func, effector_map=None, limiter_map=None, skip_null=False):
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_WALKING_BITS_SIZE:
        end = MAX_WALKING_BITS_SIZE

    for i in range(start, end):
        if limiter_map:
            if not limiter_map[i]:
                continue

        if skip_null and not data[i]:
            continue

        data[i] ^= 0xFF
        bitmap, _ = func(irp_list, label="afl_flip_8/1")
        # if effector_map and orig_bitmap == bitmap:
        #     effector_map[i] = 0
        data[i] ^= 0xFF


def mutate_seq_two_walking_bytes(irp_list, index, func, effector_map=None, skip_null=False):
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_WALKING_BITS_SIZE:
        end = MAX_WALKING_BITS_SIZE

    if len(data) <= 1:
        return

    for i in range(start, end-1):
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        func(irp_list, label="afl_flip_8/2")
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF


def mutate_seq_four_walking_bytes(irp_list, index, func, effector_map=None, skip_null=False):
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_WALKING_BITS_SIZE:
        end = MAX_WALKING_BITS_SIZE

    if len(data) <= 3:
        return

    for i in range(start, end-3):

        if effector_map:
            if effector_map[i:i+4] == bytes(4):
                continue

        if skip_null and data[i:i+4] == bytes(4):
            continue

        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        data[i+2] ^= 0xFF
        data[i+3] ^= 0xFF
        func(irp_list, label="afl_flip_8/4")
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        data[i+2] ^= 0xFF
        data[i+3] ^= 0xFF
