"""Формат пакетів ЛР №2.

Пакет на дроті:  | довжина (4 б) | CRC16 (2 б) | шифротекст (N б) |
  - довжина  — N, беззнакове ціле, мережевий порядок байтів;
  - CRC16    — контрольна сума ВІДКРИТОГО тексту (перевірка цілісності);
  - шифротекст — JSON-об'єкт у UTF-8, зашифрований зсувом на 7.
"""
import json
import struct

from crypto import crc16, shift_decrypt, shift_encrypt

PORT = 7700                         # TCP і UDP
DISCOVER_REQUEST = b"LAB2_DISCOVER"
DISCOVER_REPLY = "LAB2_SERVER"
ENCODING = "utf-8"
HEADER = struct.Struct("!IH")
MAX_PACKET = 64 * 1024


class ProtocolError(Exception):
    """Порушення формату або цілісності пакета."""


def _recv_exact(sock, n):
    chunks, received = [], 0
    while received < n:
        chunk = sock.recv(n - received)
        if not chunk:
            if received == 0:
                return None
            raise ProtocolError("З'єднання розірвано посеред пакета")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def encode_packet(obj: dict) -> bytes:
    plain = json.dumps(obj, ensure_ascii=False).encode(ENCODING)
    if len(plain) > MAX_PACKET:
        raise ProtocolError(f"Пакет завеликий ({len(plain)} байт)")
    return HEADER.pack(len(plain), crc16(plain)) + shift_encrypt(plain)


def send_packet(sock, obj: dict) -> None:
    sock.sendall(encode_packet(obj))


def recv_packet(sock):
    """Отримати пакет. Повертає None, якщо співрозмовник закрив з'єднання."""
    header = _recv_exact(sock, HEADER.size)
    if header is None:
        return None
    length, checksum = HEADER.unpack(header)
    if length > MAX_PACKET:
        raise ProtocolError(f"Заявлена довжина {length} перевищує ліміт")
    body = _recv_exact(sock, length) if length else b""
    if body is None:
        raise ProtocolError("З'єднання розірвано посеред пакета")
    plain = shift_decrypt(body)
    if crc16(plain) != checksum:
        raise ProtocolError("Порушено цілісність пакета (CRC16 не збігається)")
    try:
        obj = json.loads(plain.decode(ENCODING))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"Некоректний вміст пакета: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("Пакет має містити JSON-об'єкт")
    return obj
