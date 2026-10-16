"""Клієнт віддаленого доступу до захищених даних (ЛР №2, варіант 1).

Запуск:  python client.py            — пошук сервера через UDP
         python client.py --host IP  — підключення за відомою адресою
"""
import argparse
import os
import socket
import sys

from crypto import auth_proof, dh_keypair, dh_shared, password_hash
from protocol import (DISCOVER_REPLY, DISCOVER_REQUEST, PORT, ProtocolError,
                      recv_packet, send_packet)

MIN_PASSWORD = 4

HELP_TEXT = """\
================================ ДОВІДКА ================================
Автор:      Бушний Андрій Андрійович, група ЗК-51мн, КПІ ім. Ігоря Сікорського
Дисципліна: Захист інформації
Робота:     ЛР №2 «Розробка клієнт-сервера віддаленого доступу
            до захищених даних», варіант 1
Завдання:   пошук сервера (UDP), режими адміністратора ADMIN і
            звичайного користувача (TCP), порт 7700.
            Адміністратор: зміна пароля, додавання та блокування
            користувачів, завершення сесії.
            Користувач: зміна пароля, отримання документа,
            завершення сесії.
            3 невірні паролі поспіль — завершення сеансу.
Захист:     автентифікація з обміном ключами Діффі–Хеллмана,
            шифрування пакетів зсувом на 7 символів,
            контроль цілісності пакетів CRC16.
=========================================================================="""


# ------------------------------------------------------------ введення пароля
def read_password(prompt: str) -> str:
    """Прочитати пароль, показуючи замість кожного символу '*'."""
    print(prompt, end="", flush=True)
    if not sys.stdin.isatty():                    # введення з файлу/каналу
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        password = line.rstrip("\r\n")
        print("*" * len(password))
        return password
    chars = []
    if os.name == "nt":
        import msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in ("\x00", "\xe0"):            # службові клавіші (стрілки)
                msvcrt.getwch()
                continue
            if ch == "\x08":
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
                continue
            chars.append(ch)
            print("*", end="", flush=True)
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    break
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch in ("\x7f", "\x08"):
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                chars.append(ch)
                sys.stdout.write("*")
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    print()
    return "".join(chars)


def read_new_password(salt: str) -> int:
    """Запитати новий пароль двічі; повернути його хеш для сервера."""
    while True:
        first = read_password("Новий пароль: ")
        if len(first) < MIN_PASSWORD:
            print(f"Пароль має містити щонайменше {MIN_PASSWORD} символи.")
            continue
        second = read_password("Підтвердіть пароль: ")
        if first != second:
            print("Паролі не збігаються, спробуйте ще раз.")
            continue
        return password_hash(salt, first)


# ------------------------------------------------------------ пошук сервера
def discover(timeout=1.5, retries=3):
    """Знайти сервер широкомовним UDP-запитом на порт 7700."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp.settimeout(timeout)
        for attempt in range(1, retries + 1):
            print(f"Пошук сервера (UDP, порт {PORT}), спроба {attempt}...")
            for target in ("255.255.255.255", "127.0.0.1"):
                try:
                    udp.sendto(DISCOVER_REQUEST, (target, PORT))
                except OSError:
                    pass
            try:
                data, addr = udp.recvfrom(1024)
            except socket.timeout:
                continue
            parts = data.decode(errors="replace").split()
            if len(parts) >= 2 and parts[0] == DISCOVER_REPLY:
                name = parts[2] if len(parts) > 2 else "?"
                print(f"Знайдено сервер '{name}' за адресою "
                      f"{addr[0]}:{parts[1]}")
                return addr[0], int(parts[1])
    return None


# ------------------------------------------------------------ сеанс
class Client:
    def __init__(self, sock):
        self.sock = sock
        self.key = None
        self.salt = None
        self.role = None

    def call(self, **obj):
        send_packet(self.sock, obj)
        reply = recv_packet(self.sock)
        if reply is None:
            raise ConnectionError("Сервер закрив з'єднання")
        if reply.get("fatal"):
            print(f"!! {reply.get('message')}")
            raise SystemExit(1)
        return reply

    def handshake(self):
        private, public = dh_keypair()
        reply = self.call(type="hello", A=public)
        self.key = dh_shared(private, reply.get("B"))
        print("Захищений сеанс встановлено (обмін ключами Діффі–Хеллмана).")

    def login(self):
        while True:
            name = input("Ім'я користувача: ").strip()
            if not name:
                continue
            reply = self.call(type="login", user=name)
            if reply["status"] == "retry":
                print(f"{reply['message']}. Залишилось спроб: "
                      f"{reply['attempts_left']}")
                continue
            break
        self.salt = reply["salt"]
        if reply["status"] == "setup":
            print("Перший вхід: встановіть пароль.")
            reply = self.call(type="setup",
                              hash=read_new_password(self.salt))
        else:
            while True:
                password = read_password("Пароль: ")
                proof = auth_proof(self.key,
                                   password_hash(self.salt, password))
                reply = self.call(type="auth", proof=proof)
                if reply["status"] != "retry":
                    break
                print(f"{reply['message']}. Залишилось спроб: "
                      f"{reply['attempts_left']}")
        self.role = reply["role"]
        print(f"Вхід виконано: {reply['user']} "
              f"({'адміністратор' if self.role == 'admin' else 'користувач'})")

    # ---------------------------------------------------------- дії
    def change_password(self):
        current = read_password("Поточний пароль: ")
        proof = auth_proof(self.key, password_hash(self.salt, current))
        new_hash = read_new_password(self.salt)
        reply = self.call(type="cmd", name="change_password",
                          proof=proof, new_hash=new_hash)
        self.show(reply)

    def add_user(self):
        name = input("Ім'я нового користувача: ").strip()
        self.show(self.call(type="cmd", name="add_user", user=name))

    def block_user(self):
        name = input("Ім'я користувача для блокування: ").strip()
        self.show(self.call(type="cmd", name="block_user", user=name))

    def list_users(self):
        reply = self.call(type="cmd", name="list_users")
        if reply["status"] != "ok":
            return self.show(reply)
        header = "Ім'я"
        print(f"{header:<16}{'Статус':<14}Пароль")
        for u in reply["users"]:
            status = "заблоковано" if u["blocked"] else "активний"
            pwd = "встановлено" if u["has_password"] else "не задано"
            print(f"{u['name']:<16}{status:<14}{pwd}")

    def get_document(self):
        reply = self.call(type="cmd", name="get_document")
        if reply["status"] != "ok":
            return self.show(reply)
        print(f"----- {reply['document']} -----")
        print(reply["content"].rstrip())
        print("-" * (len(reply["document"]) + 12))

    def raw(self, cmd):
        """Надіслати довільну команду (для перевірки блокування функцій)."""
        self.show(self.call(type="cmd", name=cmd))

    @staticmethod
    def show(reply):
        mark = ">>" if reply.get("status") == "ok" else "!!"
        if reply.get("status") == "retry":
            print(f"!! {reply['message']}. Залишилось спроб: "
                  f"{reply['attempts_left']}")
        else:
            print(f"{mark} {reply.get('message', '')}")

    def menu(self):
        if self.role == "admin":
            items = [("1", "Змінити пароль адміністратора",
                      self.change_password),
                     ("2", "Додати користувача", self.add_user),
                     ("3", "Заблокувати користувача", self.block_user),
                     ("4", "Список користувачів", self.list_users)]
        else:
            items = [("1", "Змінити пароль", self.change_password),
                     ("2", "Отримати документ", self.get_document)]
        items.append(("h", "Довідка", lambda: print(HELP_TEXT)))
        items.append(("0", "Завершити сесію", None))
        actions = {key: action for key, _, action in items}
        while True:
            print()
            for key, title, _ in items:
                print(f"  {key}. {title}")
            choice = input("Оберіть дію: ").strip().lower()
            if choice == "0":
                self.show(self.call(type="cmd", name="logout"))
                return
            if choice.startswith("/"):            # прихована команда тесту
                self.raw(choice[1:])
            elif choice in actions:
                actions[choice]()
            else:
                print("Невідома дія. 'h' — довідка.")


def main():
    parser = argparse.ArgumentParser(description="Клієнт ЛР №2")
    parser.add_argument("--host", help="адреса сервера (без пошуку UDP)")
    args = parser.parse_args()

    print("Secure Access Client (ЛР №2, варіант 1). 'h' у меню — довідка.")
    if args.host:
        address = (args.host, PORT)
    else:
        address = discover()
        if address is None:
            print("Сервер не знайдено. Перевірте, що server.py запущено, "
                  "або вкажіть --host.")
            sys.exit(1)
    try:
        with socket.create_connection(address, timeout=15) as sock:
            client = Client(sock)
            client.handshake()
            client.login()
            client.menu()
    except (ConnectionError, ProtocolError, socket.timeout, OSError) as exc:
        print(f"Помилка зв'язку з сервером: {exc}")
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nРоботу клієнта перервано.")
    print("Terminate application.")


if __name__ == "__main__":
    main()
