import base64
import hashlib
import time
import sys
from pwn import *

pattern0 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┘", " "]
pattern1 = [" ", " ", "─", "┐", " ", " ", " ",
            " ", " ", " ", "│", " ", " ", " ",
            " ", " ", " ", "│", " ", " ", " ",
            " ", " ", " ", "│", " ", " ", " ",
            " ", " ", "─", "┴", "─", " ", " "]
pattern2 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", "┌", "─", "─", "─", "┘", " ",
            " ", "│", " ", " ", " ", " ", " ",
            " ", "└", "─", "─", "─", "┘", " "]
pattern3 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", " ", "─", "─", "─", "┤", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┘", " "]
pattern4 = [" ", "│", " ", " ", " ", "│", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┤", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", " ", " ", " ", " ", "│", " "]
pattern5 = [" ", "┌", "─", "─", "─", "─", " ",
            " ", "│", " ", " ", " ", " ", " ",
            " ", "└", "─", "─", "─", "┐", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┘", " "]
pattern6 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", "│", " ", " ", " ", " ", " ",
            " ", "├", "─", "─", "─", "┐", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┘", " "]
pattern7 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", " ", " ", " ", " ", "│", " ",]
pattern8 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "├", "─", "─", "─", "┤", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┘", " "]
pattern9 = [" ", "┌", "─", "─", "─", "┐", " ",
            " ", "│", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┤", " ",
            " ", " ", " ", " ", " ", "│", " ",
            " ", "└", "─", "─", "─", "┘", " "]
patternplus = [" ", " ", " ", " ", " ", " ", " ",
                " ", " ", " ", "│", " ", " ", " ",
                " ", "─", "─", "┼", "─", "─", " ",
                " ", " ", " ", "│", " ", " ", " ",
                " ", " ", " ", " ", " ", " ", " "]
patternminus = [" ", " ", " ", " ", " ", " ", " ",
                " ", " ", " ", " ", " ", " ", " ",
                " ", "─", "─", "─", "─", "─", " ",
                " ", " ", " ", " ", " ", " ", " ",
                " ", " ", " ", " ", " ", " ", " "]
patternmult = [" ", " ", " ", " ", " ", " ", " ",
                " ", " ", "╲", " ", "╱", " ", " ",
                " ", " ", " ", "╳", " ", " ", " ",
                " ", " ", "╱", " ", "╲", " ", " ",
                " ", " ", " ", " ", " ", " ", " "]
patterndiv = [" ", " ", " ", " ", " ", " ", " ",
                " ", " ", " ", "•", " ", " ", " ",
                " ", "─", "─", "─", "─", "─", " ",
                " ", " ", " ", "•", " ", " ", " ",
                " ", " ", " ", " ", " ", " ", " "]

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break
    print(time.time(), "done.")
    r.sendlineafter(b'string S: ', base64.b64encode(solved))

def list_comp(list, pattern):
    for i in range(35):
        if list[i] != pattern[i]:
            return False
    return True
            
def str_to_int(list):
    num = ''
    if list_comp(list, pattern0):
        num = '0'
    elif list_comp(list, pattern1):
        num = '1'
    elif list_comp(list, pattern2):
        num = '2'
    elif list_comp(list, pattern3):
        num = '3'
    elif list_comp(list, pattern4):
        num = '4'
    elif list_comp(list, pattern5):
        num = '5'
    elif list_comp(list, pattern6):
        num = '6'
    elif list_comp(list, pattern7):
        num = '7'
    elif list_comp(list, pattern8):
        num = '8'
    elif list_comp(list, pattern9):
        num = '9'
    elif list_comp(list, patternplus):
        num = '+'
    elif list_comp(list, patternminus):
        num = '-'
    elif list_comp(list, patternmult):
        num = '*'
    elif list_comp(list, patterndiv):
        num = '/'
    return num

if __name__ == "__main__":
    r = remote('up.zoolab.org', 10681)
    solve_pow(r)

    r.recvuntil(b'Please complete the ')
    question_num = int(r.recvuntil(b' challenges').decode().split(" ")[0])
    for i in range(question_num):
        r.recvuntil(b': ')
        q = r.recvuntil(b' = ?').decode().split(" ")[0]
        b64 = base64.decodebytes(q.encode())
        sys.stdout.buffer.write(b64)
        b64_str = b64.decode()
        num1 = []
        num2 = []
        num3 = []
        num4 = []
        num5 = []
        num6 = []
        num7 = []
        for j in range(5):
            line = b64_str.split('\n')[j]
            counter = 1
            change_word = 1
            for k in line:
                if change_word == 1:
                    num1.append(k)
                elif change_word == 2:
                    num2.append(k)
                elif change_word == 3:
                    num3.append(k)
                elif change_word == 4:
                    num4.append(k)
                elif change_word == 5:
                    num5.append(k)
                elif change_word == 6:
                    num6.append(k)
                elif change_word == 7:
                    num7.append(k)
                if counter % 7 == 0:
                    change_word += 1
                    counter = 0
                counter += 1

        num = ''
        num += str_to_int(num1)
        num += str_to_int(num2)
        num += str_to_int(num3)
        num += str_to_int(num4)
        num += str_to_int(num5)
        num += str_to_int(num6)
        if change_word == 8:
            num += str_to_int(num7)
        sum = str(int(eval(num))).encode()
        print(sum)
        r.sendline(sum)

    r.interactive()
    r.close()