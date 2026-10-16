"""Криптографічні примітиви ЛР №2 (варіант 1).

- шифр зсуву на 7 символів (байтів);
- контрольна сума CRC16 (CRC-16/CCITT-FALSE);
- обмін ключами Діффі–Хеллмана (група 14, RFC 3526).

Усі алгоритми реалізовано власноруч, без зовнішніх бібліотек.
"""
import secrets

# ---------------------------------------------------------------- шифр зсуву
SHIFT = 7
_ENC_TABLE = bytes((i + SHIFT) % 256 for i in range(256))
_DEC_TABLE = bytes((i - SHIFT) % 256 for i in range(256))


def shift_encrypt(data: bytes) -> bytes:
    """Зсув кожного байта на +7 за модулем 256."""
    return data.translate(_ENC_TABLE)


def shift_decrypt(data: bytes) -> bytes:
    """Зворотний зсув кожного байта на -7 за модулем 256."""
    return data.translate(_DEC_TABLE)


# ---------------------------------------------------------------- CRC16
CRC16_POLY = 0x1021
CRC16_INIT = 0xFFFF


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: поліном 0x1021, початкове значення 0xFFFF."""
    crc = CRC16_INIT
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ CRC16_POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------- Діффі–Хеллман
# 2048-бітове безпечне просте число з RFC 3526 (група 14), генератор 2
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
DH_G = 2
DH_KEY_BYTES = 256


def dh_keypair():
    """Згенерувати закритий ключ і відкритий ключ g^x mod p."""
    private = secrets.randbelow(DH_P - 3) + 2
    return private, pow(DH_G, private, DH_P)


def dh_shared(private: int, other_public: int) -> bytes:
    """Обчислити спільний секрет. Відкидає тривіальні значення ключа."""
    if not isinstance(other_public, int) or not 2 <= other_public <= DH_P - 2:
        raise ValueError("Некоректний відкритий ключ Діффі–Хеллмана")
    return pow(other_public, private, DH_P).to_bytes(DH_KEY_BYTES, "big")


# ---------------------------------------------------------------- паролі
def new_salt() -> str:
    return secrets.token_hex(8)


def password_hash(salt: str, password: str) -> int:
    """Хеш пароля, що зберігається на сервері: CRC16(сіль || пароль)."""
    return crc16(bytes.fromhex(salt) + password.encode("utf-8"))


def auth_proof(session_key: bytes, pwd_hash: int) -> int:
    """Доказ знання пароля для поточного сеансу: CRC16(K || хеш)."""
    return crc16(session_key + pwd_hash.to_bytes(2, "big"))
