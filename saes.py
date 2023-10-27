class sAes:
    def __init__(self):
        self.S_BOX = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]

        # Inverse S-Box for InvSubBytes step
        self.INV_S_BOX = [
            [0xA, 0x5, 0x9, 0xB],
            [0x1, 0x7, 0x8, 0xF],
            [0x6, 0x0, 0x2, 0x3],
            [0xC, 0x4, 0xD, 0xE]
        ]
    def xor(self, a, b):
        return a ^ b
    # 半字节替代
def sub_bytes(self, state):
    """SubBytes step for S-AES."""
    new_state = [[0, 0], [0, 0]]
    for i in range(2):
        for j in range(2):
            nibble = state[i][j]
            # 使用半字节的最左侧2位作为S盒的行索引
            sbox_row = (nibble >> 2) & 0x03
            # 使用半字节的最右侧2位作为S盒的列索引
            sbox_col = nibble & 0x03
            # 使用这两个索引从S盒中查找新的半字节值
            new_nibble = self.S_BOX[sbox_row][sbox_col]
            new_state[i][j] = new_nibble
    return new_state
    # 逆半字节替代
    def inv_sub_bytes(self, state):
        """Inverse SubBytes step for S-AES."""
        new_state = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                nibble = state[i][j]
                # 使用半字节的最左侧2位作为逆S盒的行索引
                sbox_row = (nibble >> 2) & 0x03
                # 使用半字节的最右侧2位作为逆S盒的列索引
                sbox_col = nibble & 0x03
                # 使用这两个索引从逆S盒中查找新的半字节值
                new_nibble = self.INV_S_BOX[sbox_row][sbox_col]
                new_state[i][j] = new_nibble
        return new_state
    # 行移位
    def shift_rows(self,state):
        new_state = []
        for i, row in enumerate(state):
            new_row = row[-i:] + row[:-i]
            new_state.append(new_row)
        return new_state
    # 逆行移位,即行移位的逆运算
    def inv_shift_rows(self,state):
        return self.shift_rows(state)
    # 列混淆
    # 有限域GF(2^4)上的乘法
    def gf_mult(self,a, b):
        p = 0
        for counter in range(4):
            if b & 1: p ^= a
            hi_bit_set = a & 0x8
            a <<= 1
            if hi_bit_set: a ^= 0x13
            b >>= 1
        return p % 0x10
    # 列混淆
    def mix_columns(self,state):
        new_state = []
        column_1=[]
        column_2=[]
        for row in state:
            column_1.append(row[0])
            column_2.append(row[1])
        new_row_1 = []
        new_row_2 = []
        new_row_1.append(column_1[0] ^ self.gf_mult(4, column_1[1]))
        new_row_1.append(column_2[0] ^ self.gf_mult(4, column_2[1]))
        new_row_2.append(self.gf_mult(4, column_1[0]) ^ column_1[1])
        new_row_2.append(self.gf_mult(4, column_2[0]) ^ column_2[1])
        new_state.append(new_row_1)
        new_state.append(new_row_2)
        return new_state
    # 逆列混淆
    def inv_mix_columns(self,state):
        new_state = []
        column_1 = []
        column_2 = []
        for row in state:
            column_1.append(row[0])
            column_2.append(row[1])
        new_row_1 = []
        new_row_2 = []
        new_row_1.append(self.gf_mult(9, column_1[0]) ^ self.gf_mult(2, column_1[1]))
        new_row_1.append(self.gf_mult(9, column_2[0]) ^ self.gf_mult(2, column_2[1]))
        new_row_2.append(self.gf_mult(2, column_1[0]) ^ self.gf_mult(9, column_1[1]))
        new_row_2.append(self.gf_mult(2, column_2[0]) ^ self.gf_mult(9, column_2[1]))
        new_state.append(new_row_1)
        new_state.append(new_row_2)
        return new_state

    # 密钥扩展
    def rot_nib(self,word):
        """Rotate the nibbles of an 8-bit word."""
        return (word << 4 | word >> 4) & 0xFF

    def sub_nib(self, word):
        """Substitute the nibbles of an 8-bit word using the S-Box."""

        # 高4位半字节
        high_nibble = (word >> 4) & 0x0F
        sbox_row_high = (high_nibble >> 2) & 0x03
        sbox_col_high = high_nibble & 0x03
        new_high_nibble = self.S_BOX[sbox_row_high][sbox_col_high]

        # 低4位半字节
        low_nibble = word & 0x0F
        sbox_row_low = (low_nibble >> 2) & 0x03
        sbox_col_low = low_nibble & 0x03
        new_low_nibble = self.S_BOX[sbox_row_low][sbox_col_low]

        # 组合新的8位字
        return (new_high_nibble << 4) | new_low_nibble

    def key_expansion(self,key):
        """Key expansion for S-AES."""
        w = [   key >> 8, key & 0xFF]  # Split the 16-bit key into two 8-bit parts: w0 and w1
        temp1=128
        temp2=48
        # Compute w2
        g_w1 = self.sub_nib(self.rot_nib(w[1]))
        w2 = w[0] ^ temp1 ^g_w1
        # Compute w3
        w3 = w2 ^ w[1]
        # Compute w4
        g_w3 = self.sub_nib(self.rot_nib(w3))
        w4 = w2 ^ temp2 ^ g_w3
        # Compute w5
        w5 = w4 ^ w3
        return [w[0], w[1], w2, w3, w4, w5]

    def encrypt(self, plaintext, key):
        expanded_keys = self.key_expansion(key)
        round_keys = []
        for k in expanded_keys:
            binary_key = bin(k)[2:].zfill(8)
            round_keys.append(binary_key[:4])
            round_keys.append(binary_key[4:])
        #print("Round keys:", round_keys)
        # 轮密钥加
        state = [[plaintext[0][0] ^ int(round_keys[0], 2), plaintext[0][1] ^ int(round_keys[2], 2)],
                 [plaintext[1][0] ^ int(round_keys[1], 2), plaintext[1][1] ^ int(round_keys[3], 2)]]
        #print("After initial round key addition:", state)

        # 第1轮
        state = self.sub_bytes(state)
        #print("After SubBytes (Round 1):", state)
        state = self.shift_rows(state)
        #print("After ShiftRows (Round 1):", state)
        state = self.mix_columns(state)
        #print("After MixColumns (Round 1):", state)
        state = [[state[0][0] ^ int(round_keys[4], 2), state[0][1] ^ int(round_keys[6], 2)],
                 [state[1][0] ^ int(round_keys[5], 2), state[1][1] ^ int(round_keys[7], 2)]]
        #print("After round key addition (Round 1):", state)

        # 第2轮
        state = self.sub_bytes(state)
        #print("After SubBytes (Round 2):", state)
        state = self.shift_rows(state)
        #print("After ShiftRows (Round 2):", state)
        state = [[state[0][0] ^ int(round_keys[8], 2), state[0][1] ^ int(round_keys[10], 2)],
                 [state[1][0] ^ int(round_keys[9], 2), state[1][1] ^ int(round_keys[11], 2)]]
        #print("After final round key addition:", state)

        return state

    def decrypt(self, ciphertext, key):
        expanded_keys = self.key_expansion(key)
        round_keys = []
        for k in expanded_keys:
            binary_key = bin(k)[2:].zfill(8)
            round_keys.append(binary_key[:4])
            round_keys.append(binary_key[4:])

        # 初始轮密钥加
        state = [[ciphertext[0][0] ^ int(round_keys[8], 2), ciphertext[0][1] ^ int(round_keys[10], 2)],
                 [ciphertext[1][0] ^ int(round_keys[9], 2), ciphertext[1][1] ^ int(round_keys[11], 2)]]

        # 第1轮
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = [[state[0][0] ^ int(round_keys[4], 2), state[0][1] ^ int(round_keys[6], 2)],
                 [state[1][0] ^ int(round_keys[5], 2), state[1][1] ^ int(round_keys[7], 2)]]
        state = self.inv_mix_columns(state)

        # 第2轮
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = [[state[0][0] ^ int(round_keys[0], 2), state[0][1] ^ int(round_keys[2], 2)],
                 [state[1][0] ^ int(round_keys[1], 2), state[1][1] ^ int(round_keys[3], 2)]]

        return state

#
# aes = sAes()
# plaintext = [[0x15, 0x2], [0x4, 0x9]]
# key = 0xa73b
#
# print("原始明文：", plaintext)
# ciphertext = aes.encrypt(plaintext, key)
# print("加密后的密文：", ciphertext)
#
# decrypted_plaintext = aes.decrypt(ciphertext, key)
# print("解密后的明文：", decrypted_plaintext)
