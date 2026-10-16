"""Сервер віддаленого доступу до захищених даних (ЛР №2, варіант 1).

Запуск:  python server.py
UDP 7700 — відповідає на пошук сервера; TCP 7700 — сеанси користувачів.
"""
import json
import os
import re
import socket
import sys
import threading
from datetime import datetime

from crypto import (auth_proof, dh_keypair, dh_shared, new_salt)
from protocol import (DISCOVER_REPLY, DISCOVER_REQUEST, PORT, ProtocolError,
                      recv_packet, send_packet)

BASE = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE, "users.json")
DOCUMENT_FILE = os.path.join(BASE, "document.txt")
SERVER_NAME = socket.gethostname()
ADMIN = "ADMIN"
MAX_ATTEMPTS = 3
NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

ROLE_COMMANDS = {
    "admin": {"change_password", "add_user", "block_user",
              "list_users", "logout"},
    "user": {"change_password", "get_document", "logout"},
}


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


class UserDB:
    """Список користувачів у файлі users.json (доступ під блокуванням)."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.users = json.load(f)
        else:
            self.users = {}
        if ADMIN not in self.users:            # пароль задається при 1-му вході
            self.users[ADMIN] = {"salt": new_salt(), "hash": None,
                                 "blocked": False}
            self._save()

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.users, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def get(self, name):
        with self.lock:
            user = self.users.get(name)
            return dict(user) if user else None

    def set_hash(self, name, pwd_hash):
        with self.lock:
            self.users[name]["hash"] = pwd_hash
            self._save()

    def add(self, name):
        with self.lock:
            if name.upper() in (n.upper() for n in self.users):
                return False
            self.users[name] = {"salt": new_salt(), "hash": None,
                                "blocked": False}
            self._save()
            return True

    def block(self, name):
        with self.lock:
            if name not in self.users:
                return False
            self.users[name]["blocked"] = True
            self._save()
            return True

    def listing(self):
        with self.lock:
            return [{"name": n, "blocked": u["blocked"],
                     "has_password": u["hash"] is not None}
                    for n, u in sorted(self.users.items())]


class SessionEnd(Exception):
    """Сеанс потрібно завершити (повідомлення вже надіслано клієнту)."""


class Session:
    def __init__(self, conn, addr, db):
        self.conn, self.db = conn, db
        self.peer = f"{addr[0]}:{addr[1]}"
        self.key = None
        self.user = None
        self.role = None
        self.failures = 0

    # ---------------------------------------------------------- допоміжні
    def send(self, **obj):
        send_packet(self.conn, obj)

    def recv(self):
        msg = recv_packet(self.conn)
        if msg is None:
            raise SessionEnd("клієнт закрив з'єднання")
        return msg

    def fail(self, message):
        """Зарахувати невдалу спробу; після третьої — завершити сеанс."""
        self.failures += 1
        left = MAX_ATTEMPTS - self.failures
        log(f"{self.peer}: невдала спроба {self.failures}/{MAX_ATTEMPTS} "
            f"({message})")
        if left <= 0:
            self.send(status="error", fatal=True,
                      message=f"{message}. Вичерпано {MAX_ATTEMPTS} спроби — "
                              f"сеанс завершено")
            raise SessionEnd("вичерпано спроби")
        self.send(status="retry", attempts_left=left, message=message)

    # ---------------------------------------------------------- етапи
    def handshake(self):
        msg = self.recv()
        if msg.get("type") != "hello":
            raise ProtocolError("Очікувався пакет hello")
        private, public = dh_keypair()
        try:
            self.key = dh_shared(private, msg.get("A"))
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc
        self.send(type="hello", B=public, server=SERVER_NAME)
        log(f"{self.peer}: обмін ключами Діффі–Хеллмана виконано")

    def login(self):
        while True:
            msg = self.recv()
            if msg.get("type") != "login":
                raise ProtocolError("Очікувався пакет login")
            name = str(msg.get("user", ""))
            user = self.db.get(name)
            if user is None:
                self.fail(f"Користувача '{name}' не знайдено")
                continue
            if user["blocked"]:
                log(f"{self.peer}: спроба входу заблокованого '{name}'")
                self.send(status="error", fatal=True,
                          message="Обліковий запис заблоковано "
                                  "адміністратором")
                raise SessionEnd("обліковий запис заблоковано")
            break

        if user["hash"] is None:                   # перший вхід
            self.send(status="setup", salt=user["salt"])
            msg = self.recv()
            new_hash = msg.get("hash")
            if msg.get("type") != "setup" or not isinstance(new_hash, int):
                raise ProtocolError("Очікувався пакет setup")
            self.db.set_hash(name, new_hash & 0xFFFF)
            log(f"{self.peer}: '{name}' встановив пароль при першому вході")
        else:
            self.send(status="challenge", salt=user["salt"])
            while True:
                msg = self.recv()
                if msg.get("type") != "auth":
                    raise ProtocolError("Очікувався пакет auth")
                if msg.get("proof") == auth_proof(self.key, user["hash"]):
                    break
                self.fail("Невірний пароль")

        self.user = name
        self.role = "admin" if name == ADMIN else "user"
        self.failures = 0
        self.send(status="ok", role=self.role, user=name)
        log(f"{self.peer}: вхід '{name}' (роль {self.role})")

    def commands(self):
        while True:
            msg = self.recv()
            if msg.get("type") != "cmd":
                raise ProtocolError("Очікувався пакет cmd")
            cmd = msg.get("name")
            current = self.db.get(self.user)
            if current is None or current["blocked"]:
                self.send(status="error", fatal=True,
                          message="Обліковий запис заблоковано — "
                                  "сеанс завершено")
                raise SessionEnd("користувача заблоковано під час сеансу")
            if cmd not in ROLE_COMMANDS[self.role]:
                log(f"{self.peer}: '{self.user}' — заборонена команда {cmd}")
                self.send(status="error",
                          message=f"Команда '{cmd}' недоступна для ролі "
                                  f"{self.role}")
                continue
            log(f"{self.peer}: '{self.user}' виконує {cmd}")
            getattr(self, "cmd_" + cmd)(msg, current)

    # ---------------------------------------------------------- команди
    def cmd_change_password(self, msg, current):
        if msg.get("proof") != auth_proof(self.key, current["hash"]):
            self.fail("Невірний поточний пароль")
            return
        new_hash = msg.get("new_hash")
        if not isinstance(new_hash, int):
            raise ProtocolError("Поле new_hash має бути цілим числом")
        self.db.set_hash(self.user, new_hash & 0xFFFF)
        self.send(status="ok", message="Пароль змінено")

    def cmd_add_user(self, msg, current):
        name = str(msg.get("user", ""))
        if not NAME_RE.match(name):
            self.send(status="error", message="Ім'я: 3–32 символи "
                      "(латинські літери, цифри, _)")
        elif not self.db.add(name):
            self.send(status="error",
                      message=f"Користувач '{name}' уже існує")
        else:
            self.send(status="ok", message=f"Користувача '{name}' додано. "
                      "Пароль він задасть при першому вході")

    def cmd_block_user(self, msg, current):
        name = str(msg.get("user", ""))
        if name == ADMIN:
            self.send(status="error",
                      message="Обліковий запис ADMIN заблокувати не можна")
        elif not self.db.block(name):
            self.send(status="error",
                      message=f"Користувача '{name}' не знайдено")
        else:
            self.send(status="ok", message=f"Користувача '{name}' "
                                           "заблоковано")

    def cmd_list_users(self, msg, current):
        self.send(status="ok", users=self.db.listing())

    def cmd_get_document(self, msg, current):
        try:
            with open(DOCUMENT_FILE, encoding="utf-8") as f:
                text = f.read()
        except OSError as exc:
            self.send(status="error", message=f"Документ недоступний: {exc}")
            return
        self.send(status="ok", document=os.path.basename(DOCUMENT_FILE),
                  content=text)

    def cmd_logout(self, msg, current):
        self.send(status="ok", message="Сеанс завершено")
        raise SessionEnd("logout")

    # ---------------------------------------------------------- головний цикл
    def run(self):
        log(f"[+] {self.peer} підключився")
        with self.conn:
            try:
                self.handshake()
                self.login()
                self.commands()
            except SessionEnd as exc:
                log(f"{self.peer}: сеанс завершено ({exc})")
            except ProtocolError as exc:
                log(f"{self.peer}: помилка протоколу: {exc}")
                try:
                    self.send(status="error", fatal=True, message=str(exc))
                except OSError:
                    pass
            except OSError as exc:
                log(f"{self.peer}: мережева помилка: {exc}")
        log(f"[-] {self.peer} відключився")


def udp_discovery():
    """Відповідати на широкомовні запити пошуку сервера."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(("", PORT))
        while True:
            try:
                data, addr = udp.recvfrom(1024)
            except OSError:
                continue
            if data.strip() == DISCOVER_REQUEST:
                reply = f"{DISCOVER_REPLY} {PORT} {SERVER_NAME}"
                udp.sendto(reply.encode(), addr)
                log(f"UDP: запит пошуку від {addr[0]}:{addr[1]} — "
                    "надіслано відповідь")


def main():
    db = UserDB(USERS_FILE)
    print("Secure Access Server (ЛР №2, варіант 1)")
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("", PORT))
        tcp.listen()
        threading.Thread(target=udp_discovery, daemon=True).start()
    except OSError as exc:
        print(f"Не вдалося запустити сервер: {exc}")
        sys.exit(1)
    log(f"Сервер '{SERVER_NAME}' слухає TCP/UDP порт {PORT}. "
        "Ctrl+C — зупинка")
    tcp.settimeout(1.0)               # щоб Ctrl+C спрацьовував і у Windows
    with tcp:
        try:
            while True:
                try:
                    conn, addr = tcp.accept()
                except socket.timeout:
                    continue
                conn.settimeout(None)
                threading.Thread(target=Session(conn, addr, db).run,
                                 daemon=True).start()
        except KeyboardInterrupt:
            print("\nСервер зупинено.")


if __name__ == "__main__":
    main()
