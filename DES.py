class DES:

    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    INVERSE_IP = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]

    E = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

    S_BOX = [

        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
         ],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
         ],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
         ],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
         ],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
         ],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
         ],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
         ],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
         ]
    ]

    P = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

    SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    PC_1 = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32]

    def __init__(self, key, mode='ECB', iv=None):
        self.__key = key  # users input key
        self.__mode = mode
        self.__iv = iv
        if self.__mode != 'ECB' and len(self.__iv) != 8:
            raise Exception('IV length error')
        self.__keys = []  # list of round keys
        self.generate_keys()  # generate all the round_keys

    @staticmethod
    def split(byte_string, n):
        return [byte_string[i:i+n] for i in range(0, len(byte_string), n)]

    @staticmethod
    def byte2bin(byte_string):
        tmp = ''.join(bin(i)[2:].zfill(8) for i in byte_string)
        return [int(i) for i in tmp]

    @staticmethod
    def bin2byte(bin_list, byte_length):
        return int(''.join(str(i) for i in bin_list), 2).to_bytes(byte_length, byteorder='big')

    def __single_encrypt(self, block):
        block = self.permutation(block, self.IP)  # apply the initial permutation
        left, right = self.split(block, 32)
        for i in range(16):

            # f function start
            d_e = self.expand(right, self.E)  # expand d to match 48 bits long
            tmp = self.xor(self.__keys[i], d_e)
            tmp = self.substitute(tmp)
            tmp = self.permutation(tmp, self.P)
            # f function end

            tmp = self.xor(left, tmp)
            left, right = right, tmp

        tmp = self.permutation(right + left, self.INVERSE_IP)
        return tmp

    def encrypt(self, plaintext):
        text_blocks = self.split(plaintext, 8)  # split the text in blocks of 8 bytes(64 bits)
        result = []

        # choose the grouping pattern
        if self.__mode == 'ECB':
            for block in text_blocks:  # encrypt all the blocks of data
                block = self.byte2bin(block)  # convert the block in bit array
                tmp = self.__single_encrypt(block)
                result += tmp  # append the current block of result to result
        elif self.__mode == 'CBC':
            iv = self.byte2bin(self.__iv)
            for block in text_blocks:
                block = self.byte2bin(block)
                tmp = self.__single_encrypt(self.xor(block, iv))
                iv = tmp
                result += tmp
        elif self.__mode == 'CFB':
            iv = self.byte2bin(self.__iv)
            for block in text_blocks:
                block = self.byte2bin(block)
                tmp = self.xor(self.__single_encrypt(iv), block)
                iv = tmp
                result += tmp
        elif self.__mode == 'OFB':
            iv = self.byte2bin(self.__iv)
            for block in text_blocks:
                block = self.byte2bin(block)
                iv = self.__single_encrypt(iv)
                tmp = self.xor(iv, block)
                result += tmp
        else:
            raise Exception('There is no such mode.')

        final_res = self.bin2byte(result, len(plaintext))
        return final_res  # return the final string of data encrypted or decrypted

    def __single_decrypt(self, block):
        block = self.permutation(block, self.IP)  # apply the initial permutation
        left, right = self.split(block, 32)
        for i in range(16):

            # f function start
            d_e = self.expand(right, self.E)  # expand d to match 48 bits long
            tmp = self.xor(self.__keys[15 - i], d_e)  # reverse order round keys
            tmp = self.substitute(tmp)
            tmp = self.permutation(tmp, self.P)
            # f function end

            tmp = self.xor(left, tmp)
            left, right = right, tmp

        tmp = self.permutation(right + left, self.INVERSE_IP)
        return tmp

    def decrypt(self, cipher):
        text_blocks = self.split(cipher, 8)  # split the text in blocks of 8 bytes(64 bits)
        if self.__mode != 'ECB' and self.__iv == b'':
            raise Exception('IV should not be empty.')
        result = []

        # choose the grouping pattern
        if self.__mode == 'ECB':
            for block in text_blocks:  # decrypt all the blocks of data
                block = self.byte2bin(block)  # convert the block in bit array
                tmp = self.__single_decrypt(block)
                result += tmp  # append the current block of result to result
        elif self.__mode == 'CBC':
            iv = self.byte2bin(self.__iv)
            for block in text_blocks:
                block = self.byte2bin(block)
                tmp = self.xor(self.__single_decrypt(block), iv)
                iv = block
                result += tmp
        elif self.__mode == 'CFB':
            iv = self.byte2bin(self.__iv)
            for index in range(len(text_blocks)):
                block = self.byte2bin(text_blocks[index])
                tmp = self.xor(self.__single_encrypt(iv), block)
                iv = block
                result += tmp
        elif self.__mode == 'OFB':
            iv = self.byte2bin(self.__iv)
            for index in range(len(text_blocks)):
                block = self.byte2bin(text_blocks[index])
                iv = self.__single_encrypt(iv)
                tmp = self.xor(iv, block)
                result += tmp
        else:
            raise Exception('There is no such mode.')

        final_res = self.bin2byte(result, len(cipher))
        return final_res  # return the final string of data encrypted or decrypted

    @staticmethod
    def expand(block, table):  # does exactly the same thing as the arrangement, but it has been renamed for clarity
        return [block[x - 1] for x in table]

    def substitute(self, d_e):
        subblocks = self.split(d_e, 6)  # split bit array into sublist of 6 bits
        result = []
        for i in range(len(subblocks)):  # for all of the sublist
            block = subblocks[i]
            row = int(str(block[0]) + str(block[5]), 2)  # get the row with the first and last bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)  # get the column with the 2 to 5th bits
            val = self.S_BOX[i][row][column]  # take the value in the S_BOX appropriated for the round 'i'
            bins = bin(val)[2:].zfill(4)  # convert the value to binary
            result += [int(x) for x in bins]  # append it to the result list
        return result

    @staticmethod
    def permutation(block, table):  # permutation the block by the table
        return [block[x - 1] for x in table]

    @staticmethod
    def xor(t1, t2):  # xor and return the result list
        if len(t1) != len(t2):
            raise Exception('two lists should have same length')
        return [x ^ y for x, y in zip(t1, t2)]

    @staticmethod
    def shift(left, right, n):  # shift the list by the value
        return left[n:] + left[:n], right[n:] + right[:n]

    def generate_keys(self):  # generates all the 16 round keys
        key = self.byte2bin(self.__key)
        key = self.permutation(key, self.PC_1)  # apply the initial permutation on the key
        left, right = self.split(key, 28)  # split it in to left part and right part

        for i in range(16):
            left, right = self.shift(left, right, self.SHIFT[i])  # shift the key
            tmp = left + right  # combine left part and right part
            self.__keys.append(self.permutation(tmp, self.PC_2))  # add the current round key into key list


if __name__ == '__main__':
    des = DES(b'12345678')
    c = des.encrypt(b'1234567887654321')
    print(c)
    print(des.decrypt(c))
