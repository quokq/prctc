import socket
import json
from os import urandom
import hashlib


class Mod:
    def __init__(self, value, mod):
        self.value = value % mod
        self.mod = mod

    def __add__(self, other):
        return Mod(self.value + other.value, self.mod)

    def __mul__(self, other):
        return Mod(self.value * other.value, self.mod)

    def __sub__(self, other):
        return Mod(self.value - other.value, self.mod)

    def inverse(self):
        return Mod(pow(self.value, -1, self.mod), self.mod)

    def __pow__(self, power):
        return Mod(pow(self.value, power, self.mod), self.mod)

    def __eq__(self, other):
        return self.value == other.value

    def __repr__(self):
        return f'Mod({self.value}, {self.mod})'


def int_from_bytes(s):
    acc = 0
    for b in s:
        acc = acc * 256 + b
    return acc


def compute_hash(data):
    """ Вычисляет SHA-256 хеш данных. """
    return hashlib.sha256(data).hexdigest()


# Ввод данных от пользователя
secret_str = input("Введите секрет: ")
n = 3
k = 3

# Переводим секрет в число
secret = int_from_bytes(secret_str.encode("utf-8"))

# Большое простое число
P = 2 ** 521 - 1

# Проверяем, что секрет меньше P
assert secret < P, "Секрет должен быть меньше простого числа P"

# Работаем с секретом в конечном поле
secret = Mod(secret, P)

# Генерируем коэффициенты многочлена
polynomial = [secret]
for i in range(k - 1):
    polynomial.append(Mod(int_from_bytes(urandom(16)), P))


# Функция для оценки многочлена
def evaluate(coefficients, x):
    acc = Mod(0, P)
    power = Mod(1, P)
    for c in coefficients:
        acc += c * power
        power *= x
    return acc


# Генерируем фрагменты секрета
shards = {}
for i in range(n):
    x = Mod(int_from_bytes(urandom(16)), P)
    y = evaluate(polynomial, x)
    nonce = int_from_bytes(urandom(8))  # Генерируем случайный одноразовый ключ
    shards[i] = (x, y, nonce)

# Вычисляем хеш секрета
secret_hash = compute_hash(secret_str.encode("utf-8"))

# Выводим все фрагменты
print("Сгенерированные части секрета:")
for i in range(n):
    x, y, nonce = shards[i]
    print(f"Часть {i + 1}: ({x.value}, {y.value}, {nonce})")


# Отправка частей секрета по сети
def send_shards_to_multiple_networks(shards, secret_hash, hosts, ports):
    for shard_index, (host, port) in enumerate(zip(hosts, ports)):
        shard = shards[shard_index]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))

            # Отправляем хеш секрета с заголовком "HASH"
            hash_message = {
                "type": "HASH",
                "data": secret_hash
            }
            s.sendall(json.dumps(hash_message).encode() + b'\n')

            # Отправляем фрагмент секрета
            x, y, nonce = shard
            shard_message = {
                "type": "SHARD",
                "x": x.value,
                "y": y.value,
                "nonce": nonce,
                "checksum": hashlib.md5(f"{x.value},{y.value},{nonce}".encode()).hexdigest()
            }
            s.sendall(json.dumps(shard_message).encode() + b'\n')
            print(f"Часть {shard_index + 1} отправлена на {host}:{port}")


hosts = ['10.0.100.5', '10.0.100.6', '10.0.100.7', '10.0.100.8']
ports = [12391, 12392, 12393, 12394]
send_shards_to_multiple_networks(shards, secret_hash, hosts, ports)
print("Части секрета отправлены на разные сетевые карты.")
