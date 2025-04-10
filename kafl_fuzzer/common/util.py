# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shutil
import sys
import tempfile
import string
import logging
from shutil import copyfile

import psutil

import kafl_fuzzer.common.color as color

logger = logging.getLogger(__name__)

import struct
import json
def u32(x, debug=None):
    try: 
        return struct.unpack('<L',x)[0]
    except:
        with open("/tmp/sangjun","wb") as f:
            f.write(debug)
        print(f"u32 error {x} {debug}")
        exit(0)
    
def p32(x): return struct.pack('<I', x)


MAX_PAYLOAD_LEN = 2**17 - 0x100

COMMAND = 4
IOCTL_CODE = 8
INBUFFER_LENGTH = 12
OUTBUFFER_LENGTH = 16

AFL_HAVOC_MIN = 256
MAX_BUFFER_LEN = 0x2000
MAX_BUFFER_LEN_HAVOC = 0x2000




MAX_WALKING_BITS_SIZE = 0x100
MAX_ARITHMETIC_SIZE = 0x100
MAX_INTERESTING_SIZE = 0x100
MAX_RAND_VALUES_SIZE = 0x100

MAX_RANGE_VALUE = 0xffffffff

interesting_length = [1<<i for i in range(20)]



class IRP:
    '''This code from kirasys's IRPT'''
    def __init__(self, IoControlCode=0, InBuffer_length=0, OutBuffer_length=0, InBuffer=b'', Command=0):
        self.Command = Command
        self.IoControlCode = u32(IoControlCode)
        self.InBuffer_length = u32(InBuffer_length)
        self.OutBuffer_length = u32(OutBuffer_length)
        if InBuffer == b'':
            self.InBuffer = bytearray( b"\xff" * self.InBuffer_length)
        else:
            self.InBuffer = bytearray(InBuffer)
        
        

def add_to_irp_list(target_list, data):

    if len(target_list)>0:
        target_list.clear()
    start =0 

    while len(data) > start:
        command = data[start: start + COMMAND]
        ioctl_code = data[start + COMMAND: start + IOCTL_CODE]
        inbuffer_length = data[start + IOCTL_CODE: start + INBUFFER_LENGTH]
        outbuffer_length = data[start + INBUFFER_LENGTH: start + OUTBUFFER_LENGTH]
        payload = data[start+OUTBUFFER_LENGTH:start+OUTBUFFER_LENGTH + u32(inbuffer_length,debug=data)].ljust(u32(inbuffer_length),b"\xff")

        start = start +u32(inbuffer_length) + OUTBUFFER_LENGTH
        target_list.append(IRP(ioctl_code, inbuffer_length, outbuffer_length, payload,command))

def serialize(target_list):
    result = b""

    try:
        is_multi_irp = True if len(target_list)>1 else False
        for index in range(len(target_list)):
            cur = target_list[index]
            result += cur.Command + p32(cur.IoControlCode) + p32(cur.InBuffer_length) + p32(cur.OutBuffer_length)  + cur.InBuffer
        return result, is_multi_irp
    except AttributeError:
        print(f"Attribute Erorr :::::::::::::::::::: {cur} {target_list}")
        exit(0)

def serialize_sangjun(headers, datas):
    result = b""

    count = 0
    header_start = 0
    data_start = 0
    while len(headers) > header_start:
        command = headers[header_start: header_start + COMMAND]
        ioctl_code = headers[header_start + COMMAND: header_start + IOCTL_CODE]
        inbuffer_length = headers[header_start + IOCTL_CODE: header_start + INBUFFER_LENGTH]
        outbuffer_length = headers[header_start + INBUFFER_LENGTH: header_start + OUTBUFFER_LENGTH]

        payload = datas[data_start: data_start + u32(inbuffer_length)]

        header_start += OUTBUFFER_LENGTH
        data_start += u32(inbuffer_length)
        result+=command + ioctl_code + inbuffer_length + outbuffer_length + payload.ljust(u32(inbuffer_length),b"\xff")
        count+=1
    if count >1:
        is_multi_irp=True
    else:
        is_multi_irp = False
    return result, is_multi_irp


irp_list = []

def parse_payload(cur):
    return cur.Command + p32(cur.IoControlCode) + p32(cur.InBuffer_length) + p32(cur.OutBuffer_length), cur.InBuffer


def parse_all(data):
    start =0 

    sequence = []
    while len(data) > start:
        command = data[start: start + COMMAND]
        ioctl_code = data[start + COMMAND: start + IOCTL_CODE]
        inbuffer_length = data[start + IOCTL_CODE: start + INBUFFER_LENGTH]
        outbuffer_length = data[start + INBUFFER_LENGTH: start + OUTBUFFER_LENGTH]
        payload = data[start+OUTBUFFER_LENGTH:start+OUTBUFFER_LENGTH + u32(inbuffer_length)].ljust(u32(inbuffer_length),b"\xff")

        start = start +u32(inbuffer_length) + OUTBUFFER_LENGTH

        sequence.append(IRP(ioctl_code, inbuffer_length, outbuffer_length, payload,command))
    return sequence


def parse_header_and_data(target_list):

    
    headers = b''
    datas = b''
    for index in range(len(target_list)):

        def steam_header_data(cur):
            return cur.Command + p32(cur.IoControlCode) + p32(cur.InBuffer_length) + p32(cur.OutBuffer_length), cur.InBuffer
        
        header, data = steam_header_data(target_list[index])

        headers += header
        datas += data
    return headers, datas






def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else MAX_RANGE_VALUE)


class Interface:
    '''This code from kirasys's IRPT'''
    def __init__(self):
        self.interface = {}

    def __getitem__(self, key):
        return self.interface[key]

    def load(self, path):
        interface_json = json.loads(open(path, 'r').read())
        for constraint in interface_json:
            iocode = int(constraint["IoControlCode"], 16)
            inbuffer_ranges = list(map(to_range, constraint["InBufferLength"]))
            outbuffer_ranges = list(map(to_range, constraint["OutBufferLength"]))

            self.interface[iocode] = {"InBufferRange": inbuffer_ranges, "OutBufferRange": outbuffer_ranges}
            if len(inbuffer_ranges) == 1 and len(inbuffer_ranges[0]) == 1:
                self.interface[iocode]["InBufferLength"] = inbuffer_ranges[0][0]
            if len(outbuffer_ranges) == 1 and len(outbuffer_ranges[0]) == 1:
                self.interface[iocode]["OutBufferLength"] = outbuffer_ranges[0][0]


    def __generateIRP(self, iocode):
        inbuffer_ranges = interface_manager[iocode]["InBufferRange"]
        outbuffer_ranges = interface_manager[iocode]["OutBufferRange"]

        inlength = 0
        outlength = 0
        for rg in inbuffer_ranges:
            inlength = max(inlength, rg.stop - 1)
        for rg in outbuffer_ranges:
            outlength = max(outlength, rg.stop - 1)

        inlength = inlength if inlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        outlength = outlength if outlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        
        irp = IRP(p32(iocode), p32(inlength), p32(outlength),Command=b"IOIO")

        return irp.Command + p32(irp.IoControlCode) + p32(irp.InBuffer_length) + p32(irp.OutBuffer_length) + irp.InBuffer
    
    
    def generate(self, seed_dir):
    
        logger.info("[+] preparing seed files with angrPT result...")

        for iocode in interface_manager.get_all_codes():
            payload = self.__generateIRP(iocode)
            with open(seed_dir+f"/{hex(iocode)}","wb") as file:
                file.write(payload)
        import time
        time.sleep(3)

    def get_all_codes(self):
        return self.interface.keys()


interface_manager = Interface()


import json
from collections import defaultdict  # Correct import statement
import random

class Dependency:
    def __init__(self):
        self.dependency = []
        self.dependency_json = None#self.load(path)
        self.path = None

    def enroll_path(self, path):
        self.path = path

    def load(self):
        dependency_json = json.loads(open(self.path, 'r').read())
        self.dependency_json = dependency_json

    def grounping(self):
        grouped_data = defaultdict(list)

        # JSON 데이터를 공유하는 메모리 주소 별로 그룹화
        for key, value in self.dependency_json.items():
            #print(key, value)
            for item in value:
                addr = item["addr"]
                grouped_data[addr].append(key)
                break
     
        # # 같은 메모리를 공유하는것끼리 리스트에 넣음 #
        def to_hex(value):  return int(value,16)

        for addr in grouped_data:
            self.dependency.append(list(map(to_hex,grouped_data[addr])))
        #print(self.dependency)
    def get_dependency(self, ioctl):
        
        target_index = -1

        for index in range(len(self.dependency)):
            if ioctl in self.dependency[index]:
                target_index = index
                break

        if target_index == -1:
            return None
        else:

            while True:
                num = random.choice(self.dependency[target_index])
                if num==ioctl:
                    continue
                else:
                    break
            return num

        assert(1==2), print("This code never be executed")



dependency_manager = Dependency()



class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# print any qemu-like processes owned by this user
def qemu_sweep(msg):
    pids = [
        p.info['pid'] for p in psutil.process_iter(['pid', 'name', 'uids'])
        if p.info['name'] == 'qemu-system-x86_64' and p.info['uids'].real == os.getuid()
    ]

    if (len(pids) > 0):
        logger.warn(msg + " " + repr(pids))

# filter available CPUs by those with existing qemu instances
def filter_available_cpus():
    def get_qemu_processes():
        for proc in psutil.process_iter(['pid', 'name']):
            if 'qemu-system-x86_64' in proc.info['name']:
                yield (proc.info['pid'])

    avail = os.sched_getaffinity(0)
    used = set()
    for pid in get_qemu_processes():
        used |= os.sched_getaffinity(pid)
    return avail, used

# pretty-printed hexdump
def hexdump(src, length=16):
    hexdump_filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c + length]
        hex_value = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and hexdump_filter[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex_value, printable))
    return ''.join(lines)

# return safely printable portion of binary input data
# use verbatim=True to maintain whitespace/formatting
def strdump(data, verbatim=False):
    dump = data.decode("utf-8", errors='backslashreplace')

    if verbatim:
        dump = ''.join([x if x in string.printable or x in "\b\x1b" else "." for x in dump])
    else:
        dump = ''.join([x if x in string.printable and x not in "\a\b\t\n\r\x0b\x0c" else "." for x in dump])
    return dump

def atomic_write(filename, data):
    # rename() is atomic only on same filesystem so the tempfile must be in same directory
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(filename), delete=False) as f:
        f.write(data)
    os.chmod(f.name, 0o644)
    os.rename(f.name, filename)

def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def find_diffs(data_a, data_b):
    first_diff = 0
    last_diff = 0
    for i in range(min(len(data_a), len(data_b))):
        if data_a[i] != data_b[i]:
            if first_diff == 0:
                first_diff = i
            last_diff = i
    return first_diff, last_diff

def prepare_working_dir(config):

    workdir   = config.workdir
    purge      = config.purge
    resume     = config.resume

    folders = ["/corpus/regular", "/corpus/crash",
               "/corpus/kasan", "/corpus/timeout",
               "/metadata", "/bitmaps", "/imports",
               "/snapshot", "/funky", "/traces", "/logs"]

    if resume and purge:
        logger.error("Cannot set both --purge and --resume at the same time. Abort.")
        return False

    if purge:
        logger.info("[+] purge : removing old dirs")
        shutil.rmtree(workdir, ignore_errors=True)
        import time
        time.sleep(2)

    try:
        for folder in folders:
            os.makedirs(workdir + folder, exist_ok=resume)
    except FileExistsError:
        logger.error("Refuse to operate on existing workdir, supply either --purge or --resume.")
        return False
    except PermissionError as e:
        logger.error(str(e))
        return False

    return True


def prepare_dependency_dir(config, dependency_list):

    workdir   = config.workdir
    resume     = config.resume

    folders = ["/dependency"]

    for ele in dependency_list:

        for ioctl_code in ele:
            folders.append("/dependency/"+hex(ioctl_code))

    try:
        for folder in folders:
            os.makedirs(workdir + folder, exist_ok=resume)
    except FileExistsError:
        logger.error("Refuse to operate on existing workdir, supply either --purge or --resume.")
        return False
    except PermissionError as e:
        logger.error(str(e))
        return False

    return True

def copy_seed_files(working_directory, seed_directory):
    if len(os.listdir(seed_directory)) == 0:
        return False

    if len(os.listdir(working_directory)) == 0:
        return False

    i = 0
    for (directory, _, files) in os.walk(seed_directory):
        for f in files:
            path = os.path.join(directory, f)
            if os.path.exists(path):
                try:
                    copyfile(path, working_directory + "/imports/" + "seed_%05d" % i)
                    i += 1
                except PermissionError:
                    logger.error("Skipping seed file %s (permission denied)." % path)
    return True


def copy_dependency_files(working_directory, depend_directory, seed_directory):
    import glob
    file_paths = glob.glob(depend_directory+"/*")
    def get_filenames_from_glob(pattern):
        filenames = [os.path.basename(path) for path in pattern]

        return filenames
    depend_exist_list = get_filenames_from_glob(file_paths)
    #logger.critical(depend_exist_list)

    for file_name in depend_exist_list:
        seed_file_paths = glob.glob(seed_directory+"/*")

        for idx in range(len(seed_file_paths)):
            if file_name in seed_file_paths[idx]:
                copyfile(seed_directory+f"/{file_name}",depend_directory+f"/{file_name}/{file_name}")
                break
    return True

def print_hprintf(msg):
    sys.stdout.write(color.FLUSH_LINE + color.HPRINTF + msg + color.ENDC)
    sys.stdout.flush()

fancy_banner = r"""
    __                        __  ___    ________
   / /_____  _________  ___  / / /   |  / ____/ /
  / //_/ _ \/ ___/ __ \/ _ \/ / / /| | / /_  / /
 / ,< /  __/ /  / / / /  __/ / / ___ |/ __/ / /___
/_/|_|\___/_/  /_/ /_/\___/_/ /_/  |_/_/   /_____/
===================================================
"""

def print_banner(msg, quiet=False):
    if not quiet:
        print(fancy_banner)
    print("<< " + color.BOLD + color.OKGREEN + msg + color.ENDC + " >>\n")

def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

def is_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False

def json_dumper(obj):
    return obj.__dict__
