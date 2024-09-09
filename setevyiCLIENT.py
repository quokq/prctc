import socket
import json
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


def compute_hash(data):
    """ Вычисляет SHA-256 хеш данных. """
    return hashlib.sha256(data).hexdigest()


def bytes_from_int(num):
    """ Преобразует целое число обратно в байты. """
    result = bytearray()
    while num > 0:
        result.append(num & 0xFF)
        num >>= 8
    return bytes(result[::-1])


# Восстановление секрета
def retrieve_original(secrets, P):
    x_s = [s[0] for s in secrets]
    acc = Mod(0, P)
    for i in range(len(secrets)):
        others = list(x_s)
        cur = others.pop(i)
        factor = Mod(1, P)
        for el in others:
            factor *= el * (el - cur).inverse()
        acc += factor * secrets[i][1]
    return acc


# Прием частей секрета по сети
def receive_shards_from_multiple_networks(hosts, ports):
    shards = []
    nonces = set()
    P = 2 ** 521 - 1

    for host, port in zip(hosts, ports):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f'Connected by {addr} on {host}:{port}')
                secret_hash = None
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    parts = data.decode().strip().split('\n')
                    for part in parts:
                        if part:
                            message = json.loads(part)
                            if message["type"] == "HASH":
                                if secret_hash is None:
                                    secret_hash = message["data"]
                            elif message["type"] == "SHARD":
                                x_str = message["x"]
                                y_str = message["y"]
                                nonce_str = message["nonce"]
                                received_checksum = message["checksum"]
                                calculated_checksum = hashlib.md5(f"{x_str},{y_str},{nonce_str}".encode()).hexdigest()

                                if received_checksum != calculated_checksum:
                                    print("Ошибка: контрольная сумма не совпадает!")
                                    return None, None

                                x = Mod(int(x_str), P)
                                y = Mod(int(y_str), P)
                                nonce = int(nonce_str)
                                if nonce in nonces:
                                    print("Ошибка: обнаружено повторное воспроизведение!")
                                    return None, None
                                nonces.add(nonce)
                                shards.append((x, y))
                                print(f"Часть получена на {host}:{port}")

    return shards, secret_hash


hosts = ['10.0.100.5', '10.0.100.6', '10.0.100.7', '10.0.100.8']
ports = [12491, 12492, 12493, 12494]
shards, original_hash = receive_shards_from_multiple_networks(hosts, ports)
if shards is None:
    print("Секрет не восстановлен из-за повторного воспроизведения.")
else:
    print("Части секрета получены.")

    # Количество частей для восстановления
    k = int(input("Введите количество частей для восстановления: "))
    selected_shards = shards[:k]

    # Восстанавливаем секрет
    retrieved_secret = retrieve_original(selected_shards, 2 ** 521 - 1)

    # Преобразуем восстановленный секрет в строку
    retrieved_secret_bytes = bytes_from_int(retrieved_secret.value)
    retrieved_secret_str = retrieved_secret_bytes.decode('utf-8')

    # Проверяем целостность секрета
    retrieved_secret_hash = compute_hash(retrieved_secret_str.encode('utf-8'))
    if retrieved_secret_hash == original_hash:
        print("Retrieved secret:", retrieved_secret_str)
        print("Секрет успешно восстановлен!")
    else:
        print("Ошибка: целостность секрета нарушена!")
