# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style havoc and splicing stage 
"""

import glob
from kafl_fuzzer.common.util import parse_all, parse_payload, read_binary_file, interface_manager, dependency_manager, interesting_length, MAX_PAYLOAD_LEN
from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.technique.havoc_handler import *
import copy

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
    global location_corpus,location_dependency
    if config.dict:
        set_dict(load_dict(config.dict))
    # AFL havoc adds these at runtime as soon as available dicts are non-empty
    if config.dict or config.redqueen:
        append_handler(havoc_dict_insert)
        append_handler(havoc_dict_replace)

    location_corpus = config.workdir + "/corpus/"
    location_dependency = config.workdir + "/dependency/"

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

def delete_insns(irp_list, func):
    retry = 10
    new_irp_list = []   

    for _ in range(retry):
        new_irp_list = copy.deepcopy(irp_list)
        pos = rand.int(len(new_irp_list))
        new_irp_list.pop(pos)
        func(new_irp_list)
        new_irp_list.clear()

def replace_insns(irp_list, func):
    last_irp = irp_list[-1]
    target_ioctl = last_irp.IoControlCode

    next_ioctl = dependency_manager.get_dependency(target_ioctl)
    if next_ioctl == None:
        return -1

    files = glob.glob(location_dependency + hex(next_ioctl) +"/*")
    rand.shuffle(files)
    retry = 10

    new_irp_list = []   

    for _ in range(retry):
        new_irp_list = copy.deepcopy(irp_list)

        target = read_binary_file(rand.select(files))
        appended_target_list = parse_all(target)
        new_irp_list.append(rand.select(appended_target_list))

        pos = rand.int(len(irp_list))
        new_irp_list = irp_list[:pos]+ new_irp_list.pop() + irp_list[pos+1:]
        func(new_irp_list)
        new_irp_list.clear()

def add_insns(irp_list, func):
    last_irp = irp_list[-1]
    target_ioctl = last_irp.IoControlCode

    next_ioctl = dependency_manager.get_dependency(target_ioctl)
    if next_ioctl == None:
        return -1

    files = glob.glob(location_dependency + hex(next_ioctl) +"/*")
    retry = 1000
    new_irp_list = []   

    for _ in range(retry):
        next_file = rand.select(files)
        next_payload = read_binary_file(next_file)

        appended_target_list = parse_all(next_payload)

        # just append 1 targets
        new_irp_list.append(rand.select(appended_target_list))

        new_irp_list = irp_list + new_irp_list
        func(new_irp_list)
        new_irp_list.clear()

    return
    

    



def mutate_random_sequence(irp_list, index, func):
    # TODO Need to more implement this.
#    x = rand.int(10)
    add_insns(irp_list, func)
    # if x < 2 and len(irp_list) >= 3:
    #     delete_insns(irp_list, func)
    # elif x < 4 and len(irp_list) >=3:
    #     replace_insns(irp_list, func)
    # else:
    #     add_insns(irp_list, func)
        

def mutate_length(irp_list, index, func):

    target = irp_list[index]

    IoControlCode = target.IoControlCode
    origin_InBufferLength = target.InBuffer_length
    origin_OutBufferLength = target.OutBuffer_length
    origin_InBuffer = copy.deepcopy(target.InBuffer)

    # if InBufferLength <= 1 or OutBufferLength <= 1:
    #     return
    
    # When Length is fixed
    if "InBufferLength" in interface_manager[IoControlCode] and \
        "OutBufferLength" in interface_manager[IoControlCode]:
        return
    
    def get_interesting_list(target_value):
            # 초기값 설정
        result_index = -1

        # 리스트를 순회하며 19보다 작은 가장 큰 값을 찾음
        for index, value in enumerate(interesting_length):
            if value < target_value:
                result_index = index
            else:
                break
        sliced_list = interesting_length[:result_index + 1]
        sliced_list.append(target_value)
        return sliced_list
    
    def get_valid_length(target, IoControlCode):
        ## Get valid Range ##
        chosen = None
        if target+"Length" not in interface_manager[IoControlCode]:
            inbuffer_ranges = interface_manager[IoControlCode][target+"Range"]
            inlength = 0
            for rg in inbuffer_ranges:
                inlength = max(inlength, rg.stop - 1)

            x =  rand.int(10)
            if x < 7:
                candidates = get_interesting_list(inlength)
                chosen = rand.select(candidates)
            else:
                #candidates = rand.int()#get_interesting_list(inlength)
                chosen = rand.int(inlength) #rand.select(candidates)
            
            if chosen > MAX_PAYLOAD_LEN:
                chosen = MAX_PAYLOAD_LEN
        return chosen
    

    retry = 8

    for _ in range(retry):
        chosen = get_valid_length("InBuffer",IoControlCode)
        if chosen is not None:
            target.InBuffer_length = chosen

            if chosen > target.InBuffer_length:
                target.InBuffer.ljust(chosen,b"\xff")
            else:
                target.InBuffer = target.InBuffer[:chosen]


        chosen = get_valid_length("OutBuffer",IoControlCode)
        if chosen is not None:
            target.OutBuffer_length = chosen


        func(irp_list)

    target.InBuffer_length = origin_InBufferLength
    target.OutBuffer_length = origin_OutBufferLength
    target.InBuffer = origin_InBuffer