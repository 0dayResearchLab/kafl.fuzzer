import struct

def p32(i):
    return struct.pack("I",i)

aaa= b"ABCDEFGTSR"#ABCDEFG
corpus = b""
corpus += b"IOIO"
corpus += p32(0x222000)# ioctl code
corpus += p32(len(aaa)) #inbufferlength
corpus += p32(19) # outbufferLength
corpus += aaa
print(bytearray(corpus))
with open("./0x222000","wb") as f:
    f.write(corpus)


aaa= b"ABCDEFGTSR"#ABCDEFG
corpus = b""
corpus += b"IOIO"
corpus += p32(0x222004)# ioctl code
corpus += p32(len(aaa)) #inbufferlength
corpus += p32(19) # outbufferLength
corpus += aaa
print(bytearray(corpus))
with open("./0x222004","wb") as f:
    f.write(corpus)


aaa= b"ABCDEFGTSR"#ABCDEFG
corpus = b""
corpus += b"IOIO"
corpus += p32(0x222008)# ioctl code
corpus += p32(len(aaa)) #inbufferlength
corpus += p32(19) # outbufferLength
corpus += aaa
print(bytearray(corpus))
with open("./0x222008","wb") as f:
    f.write(corpus)





# aaa= b"START"#ABCDEFG
# corpus = b""
# corpus += b"IOIO"
# corpus += p32(0x222004)# ioctl code
# corpus += p32(len(aaa)) #inbufferlength
# corpus += p32(19) # outbufferLength
# corpus += aaa
# print(bytearray(corpus))
# with open("./test_file","a+b") as f:
#     f.write(corpus)


# aaa= b"ABCDEFG"#ABCDEFG
# corpus = b""
# corpus += b"IOIO"
# corpus += p32(0x222008)# ioctl code
# corpus += p32(len(aaa)) #inbufferlength
# corpus += p32(19) # outbufferLength
# corpus += aaa
# print(bytearray(corpus))
# with open("./test_file","a+b") as f:
#     f.write(corpus)
# aaa= b"SSUSSU"#ABCDEFG
# corpus = b""
# corpus += b"IOIO"
# corpus += p32(0x222004)# ioctl code
# corpus += p32(len(aaa)) #inbufferlength
# corpus += p32(19) # outbufferLength
# corpus += aaa
# print(bytearray(corpus))
# with open("./seeds/0x222004","wb") as f:
#     f.write(corpus)





# aaa= b"CSECCSEC"#ABCDEFG
# corpus = b""
# corpus += b"IOIO"
# corpus += p32(0x222008)# ioctl code
# corpus += p32(len(aaa)) #inbufferlength
# corpus += p32(19) # outbufferLength
# corpus += aaa
# print(bytearray(corpus))
# with open("./seeds/0x222008","wb") as f:
#     f.write(corpus)
    
'''
Finding DeviceName...
        > DeviceName : {'\\DosDevices\\sample'}

Finding DispatchDeviceControl...
        > DispatchDeviceControl : 0x140001380

Recovering the IOCTL interface...
        > IOCTL Interface :
[   {   'InBufferLength': ['10-10'],
        'IoControlCode': '0x222000',
        'OutBufferLength': ['1-19']},
    {   'InBufferLength': ['10-10'],
        'IoControlCode': '0x222004',
        'OutBufferLength': ['1-19']}]


'''