import secrets
from gmssl import sm3


# SM2 椭圆曲线参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  # 模数 p
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC  # 系数 a
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93  # 系数 b
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123  # 阶 n
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7  # 基点 G 的 x 坐标
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0  # 基点 G 的 y 坐标
G = (Gx, Gy)  # 基点 G

INFINITY = (None, None)

# 椭圆曲线点加法
def elliptic_add(P, Q):
    if P == INFINITY: return Q
    if Q == INFINITY: return P
    # 如果两点互逆
    if (P[1] + Q[1]) % p == 0 and P[0] == Q[0]:
        return INFINITY
    if P == Q:  # 计算 2P 的情况
        # 如果点位于y轴上
        if P[0] == 0:
            return INFINITY
        lmb = (3 * P[0] * P[0] + a) * pow(2 * P[1], p - 2, p) % p
    else:  # 普通点加
        lmb = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
    x3 = (lmb * lmb - P[0] - Q[0]) % p
    y3 = (lmb * (P[0] - x3) - P[1]) % p
    return (x3, y3)

# 椭圆曲线标量乘法
def elliptic_mul(k, P):
    R = INFINITY  # 初始化无穷点
    T = P
    while k:
        if k & 1:  # 如果当前位是 1
            R = elliptic_add(R, T)
        T = elliptic_add(T, T)  # 点加倍
        k >>= 1
    return R

# 验证自定义曲线的公钥
def validate_public_key_and_curve(public_key, curve):
    raise NotImplementedError("略过实现")

# 公钥验证函数
def validate_public_key(public_key):
    # 解构公钥点 (x, y)
    x, y = public_key
    # 检查公钥是否在无穷远点
    if public_key == INFINITY:
        raise ValueError("公钥生成失败: 点在无穷远点")
    # 检查公钥在有限域Fp上
    if not (0 <= x < p and 0 <= y < p):
        raise ValueError("公钥生成失败: 点不在有限域上")
    # 检查公钥是否满足椭圆曲线方程
    if (y * y - x * x * x - a * x - b) % p != 0:
        raise ValueError("公钥生成失败: 点不满足椭圆曲线方程")
    # 检查公钥点的阶是否为 n
    if not elliptic_mul(n, public_key) == INFINITY:
        raise ValueError("公钥生成失败: 点阶数不为n")
    return True

# 生成密钥对
def generate_keypair():
    private_key = secrets.randbelow(n)  # 生成私钥 d，取值范围 [1, n-1]
    public_key = elliptic_mul(private_key, G)  # 公钥 P = dG
    return private_key, public_key

# KDF 派生函数
def kdf(z, klen):
    ct = 1
    k = b""
    while len(k) < klen:
        msg = bytearray(z + ct.to_bytes(4, 'big'))
        k += sm3.sm3_hash(msg).encode('utf-8')  # 使用 SM3 进行哈希
        ct += 1
    return k[:klen]

# 加密
def sm2_encrypt(public_key, message, curve = None):
    # 首先验证公钥
    if curve:
        validate_public_key_and_curve(public_key, curve)
    # 这代表使用了标准参数
    validate_public_key(public_key)
    m = message.encode('utf-8')  # 将消息转为字节
    k = secrets.randbelow(n)  # 随机整数 k
    C1 = elliptic_mul(k, G)  # 计算 C1 = kG
    S = elliptic_mul(k, public_key)  # 共享密钥点 S = kP
    x2, y2 = S
    t = kdf(x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big'), len(m))  # 生成对称密钥
    C2 = bytes(a ^ b for a, b in zip(m, t))  # C2 = M XOR KDF(S)
    C3 = sm3.sm3_hash(bytearray(x2.to_bytes(32, 'big') + m + y2.to_bytes(32, 'big')))  # 计算校验值 C3
    return (C1, C2, C3)

# 解密
def sm2_decrypt(private_key, ciphertext):
    C1, C2, C3 = ciphertext
    S = elliptic_mul(private_key, C1)  # 计算共享密钥点 S = dC1
    x2, y2 = S
    t = kdf(x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big'), len(C2))  # 生成对称密钥
    m = bytes(a ^ b for a, b in zip(C2, t))  # 解密 M = C2 XOR KDF(S)
    C3_check = sm3.sm3_hash(bytearray(x2.to_bytes(32, 'big') + m + y2.to_bytes(32, 'big')))  # 校验 C3
    if C3 != C3_check:
        raise ValueError("无效密钥: C3哈希校验不通过")
    return m.decode('utf-8')

# 测试代码
if __name__ == "__main__":
    # 生成密钥对
    private_key, public_key = generate_keypair()
    print("私钥:", hex(private_key))
    print("公钥:", (hex(public_key[0]), hex(public_key[1])))

    # 加密测试
    message = """Men have forgotten this truth. But you must not forget it. You become responsible, forever, for what you have tamed. """
    print("原始消息:", message)
    ciphertext = sm2_encrypt(public_key, message)
    print("加密密文:", ciphertext)

    # 解密测试
    decrypted_message = sm2_decrypt(private_key, ciphertext)
    print("解密后的消息:", decrypted_message)
