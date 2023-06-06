import random

def GenKey():
    key = bin(random.randint(2**255, 2**256-1))[2:]
    # key = '1101000001100010000101110010101000011101001100100100110011011101010100011100000111010001111100111111111000000010011001011010111111100101001010101110011101011111001110110110111110010000010111100001010110110001110101010001011101010111100100111010010001010011'
    print('Ключ:', key)
    KZY = []
    for i in range(8):
        KeyBlock = key[32 * i:32 * (i + 1)][::-1]
        KZY.append(int(KeyBlock, 2))  # 8 блоков по 32 бит в 10-ом виде
    # print('KZY =', KZY)

    # reverse_KZY = KZY[::-1]
    # K = KZY * 3 + KZY[::-1]     # 32 блока по 8 бит(25-32 раунд - ключи в обратном порядке)
    # # print(K)
    # K = KZY + KZY[::-1] * 3
    return KZY

def Func_F(L, R):
    F = ''
    for i in range(len(L)):
        F += str((int(L[i]) + int(R[i])) % 2)
    return F

def Round(OpenText_blocks, KZY):
    sbox = (
        (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
        (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
        (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
        (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
        (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
        (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
        (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
        (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
    )

    shipherText = ''
    for i in OpenText_blocks:
        L = i[::-1][:32]
        R = i[::-1][32:]
        # print('L=',L)
        # print('R=',R)

        for j in range(32):
            buffer_R = R
            X = KZY[j]
            mod = bin((int(R, 2) + X) % (2 ** 32))[2:]  # сложение R и ключа X по mod 2**32
            while len(mod) < 32:
                mod = '0' + mod
            # print('mod =', mod)

            address = []
            address_after_sbox = ''
            for k in range(8):
                address.append(int(mod[k * 4: 4 * (k + 1)], 2))
                # print('address=', address)
                address[k] = bin(sbox[::-1][k][address[k]])[2:]   #обратный порядок блоков с 8 по 1
                while len(address[k]) != 4:
                    address[k] = '0' + address[k]
                address_after_sbox += address[k]
                # print('address =', address)
                # print('address_after_sbox =', address_after_sbox)

            for k in range(11):     # <<<11
                symb = address_after_sbox[0]
                address_after_sbox = address_after_sbox[1:] + symb
                # print('symb=',symb)
            # print('R=',address_after_sbox)

            if j == 31:
                L = Func_F(L, address_after_sbox)
                R = buffer_R
            else:
                R = Func_F(L, address_after_sbox)
                L = buffer_R

        shipherText = shipherText + (L + R)[::-1]
        # print('shipherText=', shipherText)

    return shipherText

def Encrypt(OpenText, KZY):
    OpenTextBlock = ''
    OpenText_blocks64bit = []
    for i in range(len(OpenText)):
        OpenText[i] = bin(OpenText[i])[2:]
        while len(OpenText[i]) != 8:
            OpenText[i] = '0' + OpenText[i]
            # print(shipherText)
        OpenTextBlock += OpenText[i]
        # print(OpenTextBlock)

        if (len(OpenTextBlock) == 64) or (i == len(OpenText) - 1):
            OpenText_blocks64bit.append(OpenTextBlock)
            # print('shipherText size block 64 bit:', OpenText_blocks64bit)
            OpenTextBlock = ''

    while len(OpenText_blocks64bit[-1]) != 64: #добила нулями блок ОТ до 64 бит
        OpenText_blocks64bit[-1] += '0'
    print('Блоки ОТ:', OpenText_blocks64bit)
    KZY = KZY * 3 + KZY[::-1]
    print('KZY =', KZY)
    rezult = Round(OpenText_blocks64bit, KZY)
    print('rezult =', rezult)

    shipherText_dec = []
    for i in range(len(rezult) // 8):
        shipherText_dec.append(int(rezult[i * 8:8 * (i + 1)], 2))

    shipherText_dec = bytes(shipherText_dec)
    shipherText_dec = shipherText_dec.decode(encoding='cp1251', errors='ignore')

    return shipherText_dec

def Decrypt(shipherText, KZY):
    print(shipherText)
    shipherTextBlock = ''
    shipherText_blocks64bit = []
    for i in range(len(shipherText)):
        shipherText[i] = bin(shipherText[i])[2:]
        while len(shipherText[i]) != 8:
            shipherText[i] = '0' + shipherText[i]
            # print(shipherText)
        shipherTextBlock += shipherText[i]
        # print(shipherTextBlock)

        if (len(shipherTextBlock) == 64) or (i == len(shipherText) - 1):
            shipherText_blocks64bit.append(shipherTextBlock)
            # print('shipherText size block 64 bit:', shipherText_blocks64bit)
            shipherTextBlock = ''
    print('Блоки ШТ:', shipherText_blocks64bit)

    KZY = KZY + KZY[::-1] * 3
    print('KZY =', KZY)
    rezult = Round(shipherText_blocks64bit, KZY)
    print('rezult =', rezult)

    OpenText_dec = []
    for i in range(len(rezult) // 8):
        OpenText_dec.append(int(rezult[i * 8:8 * (i + 1)], 2))
    print('OpenText_dec',OpenText_dec)
    while OpenText_dec[-1] == 0:
        OpenText_dec.pop(-1)

    OpenText_dec = bytes(OpenText_dec)
    OpenText_dec = OpenText_dec.decode(encoding='cp1251', errors='ignore')

    return OpenText_dec

"""Основная часть"""

OpenText = input('Enter Open Text:')
OpenText = list(OpenText.encode(encoding='cp1251', errors='ignore'))
print(OpenText)

KZY = GenKey()

shipherText = Encrypt(OpenText, KZY)
print(shipherText)

sipherText = input('Enter Sipher Text:')
sipherText = list(sipherText.encode(encoding='cp1251', errors='ignore'))

OpenText = Decrypt(sipherText, KZY)
print(OpenText)