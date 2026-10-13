import string

c_charset = string.ascii_uppercase + string.ascii_lowercase + string.digits + '()'
cipher = "BozjB3vlZ3ThBn9bZ2jhOH93ZaH9"

def inverse_rend(s):
    def decode_ch(ch):
        f = lambda x: chr((ord(ch) - x - 2) % 26 + x)
        if ch.islower():
            return f(97)
        if ch.isupper():
            return f(65)
        return ch
    return ''.join(decode_ch(c) for c in s)

def decode(encoded_str):
    s = inverse_rend(encoded_str)
    s = s.replace('.', '')
    binary_list = []
    length = len(s)
    for i in range(0, length, 4):
        block = s[i:i+4]
        byte_num = 3 if len(block) == 4 else len(block)-1
        bin_buf = ""
        for char in block:
            idx = c_charset.index(char)
            bin_buf += f"{idx:06b}"
        for j in range(byte_num):
            seg = bin_buf[j*8 : (j+1)*8]
            binary_list.append(seg)
    raw = bytes(int(b,2) for b in binary_list if b)
    return raw

data = decode(cipher)
print("Flag:", data.decode("utf-8"))