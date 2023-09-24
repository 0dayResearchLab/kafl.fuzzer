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


import json

def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else MAX_RANGE_VALUE)


class Interface:
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


    # def __generateIRP(self, iocode):
    #     inbuffer_ranges = interface_manager[iocode]["InBufferRange"]
    #     outbuffer_ranges = interface_manager[iocode]["OutBufferRange"]

    #     inlength = 0
    #     outlength = 0
    #     for rg in inbuffer_ranges:
    #         inlength = max(inlength, rg.stop - 1)
    #     for rg in outbuffer_ranges:
    #         outlength = max(outlength, rg.stop - 1)

    #     inlength = inlength if inlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
    #     outlength = outlength if outlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        
    #     irp = IRP(p32(iocode), p32(inlength), p32(outlength),Command=b"IOIO")

    #     return irp.Command + p32(irp.IoControlCode) + p32(irp.InBuffer_length) + p32(irp.OutBuffer_Length) + irp.InBuffer
    
    
    # def generate(self, seed_dir):
       
    #     import mmh3
    #     def hash(x): mmh3.hash(x, signed=False)
    #     for iocode in interface_manager.get_all_codes():
    #         payload = self.__generateIRP(iocode)
    #         with open(seed_dir+f"/{hex(iocode)}_{str(hash(payload))}","wb") as file:
    #             file.write(payload)
    
    def get_all_codes(self):
        return self.interface.keys()


interface_manager = Interface()


#interface_manager.load("./mwfsmflt.json")
interface_manager.load("./TargetDriver.json")
print(interface_manager.interface)

outbuffer_ranges = interface_manager[2236416]["OutBufferRange"]

outlength = 0
print(outbuffer_ranges)
for rg in outbuffer_ranges:
    outlength = max(outlength, rg.stop-1)
    print(outlength)

interesting_length = [1<<i for i in range(33)]
print(interesting_length)

interesting_length = [1 << i for i in range(33)]
target_value = outlength

# 초기값 설정
result_index = -1

# 리스트를 순회하며 19보다 작은 가장 큰 값을 찾음
for index, value in enumerate(interesting_length):
    if value < target_value:
        result_index = index
    else:
        break

# 결과 출력
if result_index != -1:
    print(f"19보다 작은 가장 큰 값의 인덱스: {result_index}")
else:
    print("19보다 작은 값이 없습니다.")
sliced_list = interesting_length[:result_index + 1]
sliced_list.append(target_value)
print(sliced_list)
print(interesting_length)
# print(outlength, MAX_RANGE_VALUE)
# outlength = outlength if outlength == MAX_RANGE_VALUE else MAX_BUFFER_LEN
# print(outlength)