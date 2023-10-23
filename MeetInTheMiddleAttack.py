from saes import sAes
class MeetInTheMiddleAttack:
    def __init__(self, sAes):
        self.sAes = sAes
        self.encrypt_dict = {} # 用于存储使用K1加密后的中间状态

    def encrypt_phase(self, plaintext, key):
        return self.sAes.encrypt(plaintext, key)

    def decrypt_phase(self, ciphertext, key):
        return self.sAes.decrypt(ciphertext, key)

    def attack(self, plaintext, ciphertext):
        # Step 1: 使用所有可能的K1加密明文，并将中间状态存储在字典中
        for k1 in range(0x0000, 0x10000):  # 遍历所有16位可能的密钥
            mid_ciphertext = self.encrypt_phase(plaintext, k1)
            self.encrypt_dict[mid_ciphertext] = k1

        # Step 2: 使用所有可能的K2解密密文，并查找匹配的中间状态
        for k2 in range(0x0000, 0x10000):
            mid_plaintext = self.decrypt_phase(ciphertext, k2)
            if mid_plaintext in self.encrypt_dict:
                k1_found = self.encrypt_dict[mid_plaintext]
                return (k1_found, k2)  # 返回匹配的K1和K2

        return None, None  # 如果没有找到匹配的密钥，返回None

# 示例
sAesInstance = sAes()  # 假设你已经定义了sAes类
attackInstance = MeetInTheMiddleAttack(sAesInstance)

plaintext=[[0x6, 0x6], [0xf, 0xb]]
ciphertext=[[0x1, 0xF], [0xE, 0x6]]
k1, k2 = attackInstance.attack(plaintext, ciphertext)
print(f"Recovered Keys: K1 = {k1:04x}, K2 = {k2:04x}")
