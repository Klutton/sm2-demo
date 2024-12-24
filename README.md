# sm2-demo
a self implemented Public Key cryptographic algorithm SM2 based on elliptic curves
# quick start
```python
# 测试代码
if __name__ == "__main__":
    # 生成密钥对 ken generation
    private_key, public_key = generate_keypair()
    print("私钥:", hex(private_key))
    # 私钥: 0xd3ac52856b71a756fa8cdf3cc87a6a73d7d121fb4d70620c065f895807ec4d51
    print("公钥:", (hex(public_key[0]), hex(public_key[1])))
    # 公钥: ('0x25aeebd56eaa75e40090e6b52455faed36050994023eef659fce4a684f8a292b', '0x4d78868b4e0986aed2865421f449e6fad6962a75985cadd561defeaad51b8c5b')

    # 加密测试 encryption
    message = """Men have forgotten this truth. But you must not forget it. You become responsible, forever, for what you have tamed. """
    print("原始消息:", message)
    # 原始消息: Men have forgotten this truth. But you must not forget it. You become responsible, forever, for what you have tamed.
    ciphertext = sm2_encrypt(public_key, message)
    print("加密密文:", ciphertext)
    # 加密密文: ((68499156143338086921855979033387907869945509276802487904973362628704111822928, 6795307526971566187668271403906143819028569595497250209830300523242712708826), b'+\x00Y\x18YP\x13P\x16\x00Y\x14^\t\x15\x12S\rC\x11P\x0f\x11\x11\x10B\x14B\x0e\x19\x13 ED\x18H\x0bDA\\\x17FC\x12\r\\F\x19R\\\x17\x03\x01FB\x0f\x16\x19Aj\x0bG\x11\x07SQ]\tTDKQ\x17C[\\F\x08V[Q\x1e\x15^^G\x04E\x01\x10\x14B_XJ\x17\x13_RD\x10\x18XL\x13\rQFSDLXZ\x03\x05\x1dD', '5fdd44663de49660de219bd95dceadba5cbe1deedfa6d006be55e25619bd9a7a')

    # 解密测试 decryption
    decrypted_message = sm2_decrypt(private_key, ciphertext)
    print("解密后的消息:", decrypted_message)
    # 解密后的消息: Men have forgotten this truth. But you must not forget it. You become responsible, forever, for what you have tamed.
```
