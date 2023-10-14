import saes
# 创建sAes类的实例
aes = saes.sAes()

# 测试xor函数
print("Testing xor function:")
result = aes.xor(0xA, 0x5)
print(f"xor(0xA, 0x5) = {hex(result)}")

# 测试sub_bytes函数
print("\nTesting sub_bytes function:")
state = [[0x8, 0x1], [0xA, 0xC]]
result = aes.sub_bytes(state)
print(f"sub_bytes({state}) = {result}")

# 测试inv_sub_bytes函数
print("\nTesting inv_sub_bytes function:")
result_inv = aes.inv_sub_bytes(result)
print(f"inv_sub_bytes({result}) = {result_inv}")

# 测试shift_rows函数
print("\nTesting shift_rows function:")
state = [[0x1, 0x2], [0x3, 0x4]]
result = aes.shift_rows(state)
print(f"shift_rows({state}) = {result}")

# 测试inv_shift_rows函数
print("\nTesting inv_shift_rows function:")
result_inv = aes.inv_shift_rows(result)
print(f"inv_shift_rows({result}) = {result_inv}")

# 测试mix_columns函数
print("\nTesting mix_columns function:")
state = [[0x6, 0x4], [0xC, 0x0]]
result = aes.mix_columns(state)
print(f"mix_columns({state}) = {result}")

# 测试inv_mix_columns函数
print("\nTesting inv_mix_columns function:")
result_inv = aes.inv_mix_columns(result)
print(f"inv_mix_columns({result}) = {result_inv}")

# 测试rot_nib函数
print("\nTesting rot_nib function:")
word = 0x12
result = aes.rot_nib(word)
print(f"rot_nib({hex(word)}) = {hex(result)}")

# 测试sub_nib函数
print("\nTesting sub_nib function:")
word = 0x55
result = aes.sub_nib(word)
print(f"sub_nib({hex(word)}) = {hex(result)}")

# 测试key_expansion函数
print("\nTesting key_expansion function:")
key = 0x2D55
expanded_key = aes.key_expansion(key)
print(f"key_expansion({hex(key)}) = {[hex(w) for w in expanded_key]}")
