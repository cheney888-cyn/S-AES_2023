from saes import sAes


class Extended_sAes(sAes):
    def double_encrypt(self, plaintext, key):
        # 从32位密钥中拆分为两个16位密钥
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 使用第一个密钥加密
        intermediate_ciphertext = super().encrypt(plaintext, key1)
        # 使用第二个密钥再次加密
        final_ciphertext = super().encrypt(intermediate_ciphertext, key2)

        return final_ciphertext

    def double_decrypt(self, ciphertext, key):
        # 从32位密钥中拆分为两个16位密钥
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 使用第二个密钥解密
        intermediate_plaintext = super().decrypt(ciphertext, key2)
        # 使用第一个密钥再次解密
        final_plaintext = super().decrypt(intermediate_plaintext, key1)

        return final_plaintext

    def matrix_to_int(self,matrix):
        # Flatten the matrix
        flattened = [matrix[0][0], matrix[1][0], matrix[0][1], matrix[1][1]]

        # Convert each number to 4-bit binary representation
        bin_values = [format(val, '04b') for val in flattened]

        # Join all binary values to form a 16-bit binary string
        bin_string = ''.join(bin_values)

        # Convert the 16-bit binary string to an integer
        return int(bin_string, 2)

    def meet_in_the_middle_attack(self, plaintext, ciphertext):
        # 初始化一个空字典，用于存储中间值与密钥的映射
        intermediate_values = {}
        res = []
        # 枚举所有可能的16位密钥
        for key1 in range(0x10000):
            # 使用第一个密钥加密明文
            intermediate_value = self.matrix_to_int(self.encrypt(plaintext, key1))

            # 将中间值与第一个密钥映射存储在字典中
            intermediate_values[intermediate_value] = key1

        # 枚举所有可能的16位密钥
        for key2 in range(0x10000):
            # 使用第二个密钥解密密文
            intermediate_value = self.matrix_to_int(self.decrypt(ciphertext, key2))

            # 检查中间值是否在字典中
            if intermediate_value in intermediate_values:
                # 如果找到匹配的中间值，表示成功找到了密钥
                key1 = intermediate_values[intermediate_value]
                key2 = key2
                # 合并密钥并以16进制表示
                combined_key = "{:04X}".format((key1 << 16) | key2)
                res.append(combined_key)

        # 如果没有找到匹配的密钥，则返回None表示失败
        return res

    def triple_encrypt(self, plaintext, key1, key2, key3):
        # 使用第一个密钥K1进行加密
        ciphertext1 = self.encrypt(plaintext, key1)
        # 使用第二个密钥K2进行加密
        ciphertext2 = self.encrypt(ciphertext1, key2)
        # 使用第三个密钥K3进行加密
        ciphertext3 = self.encrypt(ciphertext2, key3)
        # 返回最终的密文
        return ciphertext3

    def triple_decrypt(self, ciphertext, key1, key2, key3):
        # 使用第三个密钥K3进行解密
        intermediate_plaintext2 = self.decrypt(ciphertext, key3)
        # 使用第二个密钥K2进行解密
        intermediate_plaintext1 = self.decrypt(intermediate_plaintext2, key2)
        # 使用第一个密钥K1进行解密
        plaintext = self.decrypt(intermediate_plaintext1, key1)
        # 返回最终的明文
        return plaintext


# 示例
aes = Extended_sAes()
plaintext = [[0x6, 0x6], [0xf, 0xb]]
key = 0x11780001
key1 = 0xa73b
key2 = 0xa24c
key3 = 0x1178
print("原始明文：", plaintext)
ciphertext = aes.double_encrypt(plaintext, key)
print("双重加密后的密文：", ciphertext)
decrypted_plaintext = aes.double_decrypt(ciphertext, key)
print("解密后的明文：", decrypted_plaintext)
keys = aes.meet_in_the_middle_attack(plaintext, ciphertext)
print("中间相遇攻击所得的可能密钥为:", keys)
print("原始明文：", plaintext)
ciphertext = aes.triple_encrypt(plaintext, key1, key2, key3)
print("三重加密后的密文：", ciphertext)
decrypted_plaintext = aes.triple_decrypt(ciphertext, key1, key2, key3)
print("解密后的明文：", decrypted_plaintext)