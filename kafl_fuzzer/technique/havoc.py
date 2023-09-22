# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style havoc and splicing stage 
"""

import glob
from kafl_fuzzer.common.util import parse_all, parse_payload, read_binary_file
from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.technique.havoc_handler import *


def load_dict(file_name):
    f = open(file_name)
    dict_entries = []
    for line in f:
        if not line.startswith("#"):
            try:
                dict_entries.append((line.split("=\"")[1].split("\"\n")[0]).encode('latin1').decode('unicode-escape').encode('latin1'))
            except:
                pass
    f.close()
    return dict_entries


def init_havoc(config):
    global location_corpus
    if config.dict:
        set_dict(load_dict(config.dict))
    # AFL havoc adds these at runtime as soon as available dicts are non-empty
    if config.dict or config.redqueen:
        append_handler(havoc_dict_insert)
        append_handler(havoc_dict_replace)

    location_corpus = config.workdir + "/corpus/"


def havoc_range(perf_score):
    max_iterations = int(2*perf_score)

    if max_iterations < AFL_HAVOC_MIN:
        max_iterations = AFL_HAVOC_MIN

    return max_iterations


def mutate_seq_havoc_array(irp_list, index, func, max_iterations, resize=False):
    # if resize:
    #     data = data + data
    # else:
    #     data = data
    data = irp_list[index].InBuffer
    InBufferLength = irp_list[index].InBuffer_length

    stacking = rand.int(AFL_HAVOC_STACK_POW2)
    stacking = 1 << (stacking)

    for _ in range(1+max_iterations//stacking):
        for _ in range(stacking):
            handler = rand.select(havoc_handler)
            data = handler(data)
            
            if len(data) >= InBufferLength:
                data = data[:InBufferLength]
            else:
                data = data.ljust(InBufferLength,b"\xff") #TO DO -> make random bytes
            
            irp_list[index].InBuffer = data

            func(irp_list)


def mutate_seq_splice_array(irp_list, index, func, max_iterations, resize=False):
    global location_corpus
    havoc_rounds = 4
    splice_rounds = max_iterations//havoc_rounds
    files = glob.glob(location_corpus + "/regular/payload_*")
    
    target = irp_list[index]
    InBufferLength = irp_list[index].InBuffer_length
    #print("mutate_seq_splice_array")
    header, data = parse_payload(target)
    for _ in range(splice_rounds):
        spliced_data = havoc_splicing(data, files)
        if spliced_data is None:
            return # could not find any suitable splice pair for this file

        if len(data) >= InBufferLength:
            spliced_data = spliced_data[:target.InBuffer_length]
        else:
            spliced_data = spliced_data.ljust(InBufferLength,b"\xff") #TO DO -> make random bytes
            
        target.InBuffer = spliced_data
        func(irp_list)
        mutate_seq_havoc_array(irp_list,
                               index,
                               func,
                               havoc_rounds,
                               resize=resize)

def mutate_random_sequence(irp_list, index, func):
    files = glob.glob(location_corpus + "/regular/payload_*")


    rand.shuffle(files)
    retry = 10
    new_irp_list = []    
    for _ in range(retry):
        #for i in range(rand.int(len(files))):

        if len(files) > 4:
            limit = 4
        else:
            limit = len(files)

        for i in range(limit):
            target = read_binary_file(files[i])

            appended_target_list = parse_all(target)
            for j in range(len(appended_target_list)):
                new_irp_list.append(appended_target_list[j])

        func(new_irp_list)
        new_irp_list.clear()