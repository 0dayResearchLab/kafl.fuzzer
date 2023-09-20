import struct

def p32(i):
    return struct.pack("I",i)

aaa= b"START"#ABCDEFG
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
