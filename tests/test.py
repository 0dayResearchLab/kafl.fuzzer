
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

COMMAND = 4
IOCTL_CODE = 8
INBUFFER_LENGTH = 12
OUTBUFFER_LENGTH = 16

AFL_HAVOC_MIN = 256
MAX_BUFFER_LEN = 0x2000
MAX_BUFFER_LEN_HAVOC = 0x2000




MAX_WALKING_BITS_SIZE = 0x400
MAX_ARITHMETIC_SIZE = 0x400
MAX_INTERESTING_SIZE = 0x400
MAX_RAND_VALUES_SIZE = 0x400

MAX_RANGE_VALUE = 0xffffffff


class IRP:
    def __init__(self, IoControlCode=0, InBuffer_length=0, OutBuffer_Length=0, InBuffer=b'', Command=0):
        self.Command = Command
        self.IoControlCode = u32(IoControlCode)
        self.InBuffer_length = u32(InBuffer_length)
        self.OutBuffer_Length = u32(OutBuffer_Length)
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
        payload = data[start+OUTBUFFER_LENGTH:start+OUTBUFFER_LENGTH + u32(inbuffer_length,debug=data)]

        start = start +u32(inbuffer_length) + OUTBUFFER_LENGTH
        target_list.append(IRP(ioctl_code, inbuffer_length, outbuffer_length, payload,command))
    
def serialize(target_list):
    result = b""

    try:

        for index in range(len(target_list)):
            cur = target_list[index]
            result += cur.Command + p32(cur.IoControlCode) + p32(cur.InBuffer_length) + p32(cur.OutBuffer_Length)  + cur.InBuffer
        return result
    except AttributeError:
        print(f"Attribute Erorr :::::::::::::::::::: {cur} {target_list}")
        exit(0)

def serialize_sangjun(headers, datas):
    result = b""

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
        result+=command + ioctl_code + inbuffer_length + outbuffer_length + payload

    return result
    # try:

    #     for index in range(len(target_list)):
    #         cur = target_list[index]
    #         result += cur.Command + cur.IoControlCode + cur.InBuffer_length + cur.OutBuffer_Length  + cur.InBuffer
    #     return result
    # except AttributeError:
    #     print(f"Attribute Erorr :::::::::::::::::::: {cur} {target_list}")
    #     exit(0)


irp_list = []

def parse_payload(cur):
    return cur.Command + p32(cur.IoControlCode) + p32(cur.InBuffer_length) + p32(cur.OutBuffer_Length), cur.InBuffer


def parse_all(data,file_name):
    start =0 

    sequence = []
    while len(data) > start:
        command = data[start: start + COMMAND]
        ioctl_code = data[start + COMMAND: start + IOCTL_CODE]
        inbuffer_length = data[start + IOCTL_CODE: start + INBUFFER_LENGTH]
        outbuffer_length = data[start + INBUFFER_LENGTH: start + OUTBUFFER_LENGTH]
        payload = data[start+OUTBUFFER_LENGTH:start+OUTBUFFER_LENGTH + u32(inbuffer_length)]

        start = start +u32(inbuffer_length) + OUTBUFFER_LENGTH
        print(f"ioctl_code : {hex(u32(ioctl_code))} inbuffer_length : {hex(u32(inbuffer_length))} outbuffer_length : {hex(u32(outbuffer_length))} data : {payload}")

        # if u32(ioctl_code) not in [0x222004,0x222000,0x222008]:
        #     print(f"this is error {file_name}")
        #     exit(0)
        sequence.append(IRP(ioctl_code, inbuffer_length, outbuffer_length, payload,command))
    return sequence


def parse_header_and_data(target_list):
    start =0 


    
    headers = b''
    datas = b''
    for index in range(len(target_list)):

        def steam_header_data(cur):
            return cur.Command + p32(cur.IoControlCode) + p32(cur.InBuffer_length) + p32(cur.OutBuffer_Length), cur.InBuffer
        
        header, data = steam_header_data(target_list[index])

        headers += header
        datas += data
    return headers, datas


def read_binary_file(path):
    with open(path,"rb") as f:
        file_data = f.read()
    return file_data

import glob

# file_list = glob.glob("./corpus/payload*")
# print(file_list)
a = parse_all(read_binary_file("corpus/payload_00088"),"corpus/payload_00088")



# for file in file_list:

#     fff = read_binary_file(file)
#     a = parse_all(fff,file)
