import base64
import os

class CryptoError(Exception):
    """Базовое исключение для ошибок шифрования."""
    pass

class KeyError(CryptoError):
    """Ошибка, связанная с ключом."""
    pass

class EncryptionError(CryptoError):
    """Ошибка шифрования или дешифрования."""
    pass

# Генерация и сохранение ключа в файл (если файла нет)
def _ensure_key_exists(key_path: str, key_length: int = 16) -> bytes:
    """Создаёт файл ключа в текстовом виде, если он ещё не существует."""
    try:
        if not os.path.exists(key_path):
            key = os.urandom(key_length)
            encoded_key = base64.b64encode(key).decode('utf-8')
            with open(key_path, 'w') as file:
                file.write(encoded_key)
        return _load_key(key_path)
    except OSError as e:
        raise KeyError(f"Ошибка при создании или записи файла ключа: {e}")

# Загрузка ключа из файла
def _load_key(key_path: str) -> bytes:
    """Загружает ключ в бинарном виде из текстового файла."""
    try:
        with open(key_path, 'r') as file:
            encoded_key = file.read()
        return base64.b64decode(encoded_key)
    except (OSError, base64.binascii.Error) as e:
        raise KeyError(f"Ошибка при загрузке ключа из файла: {e}")

# Шифрование строки с использованием IV
def encrypt(message: str, key_path: str = 'encryption_key.txt') -> str:
    """Шифрует сообщение с использованием ключа и IV."""
    try:
        key = _ensure_key_exists(key_path)  # Загружаем ключ, если он есть, или создаём новый
        message_bytes = message.encode('utf-8')
        
        # Генерируем случайный IV
        iv = os.urandom(len(key))
        
        # Применяем XOR к каждому байту сообщения с ключом и IV
        encrypted_bytes = bytearray(
            message_bytes[i] ^ key[i % len(key)] ^ iv[i % len(iv)] for i in range(len(message_bytes))
        )
        
        # Сохраняем IV вместе с зашифрованным текстом (через Base64)
        encrypted_data = iv + encrypted_bytes
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        raise EncryptionError(f"Ошибка при шифровании сообщения: {e}")

# Расшифровка строки с использованием IV
def decrypt(encrypted_message: str, key_path: str = 'encryption_key.txt') -> str:
    """Расшифровывает сообщение с использованием ключа и IV."""
    try:
        key = _ensure_key_exists(key_path)  # Загружаем ключ, если он есть, или создаём новый
        encrypted_data = base64.b64decode(encrypted_message)
        
        # Проверка длины данных
        if len(encrypted_data) < len(key):
            raise EncryptionError("Недостаточная длина данных для дешифрования.")
        
        # Извлекаем IV из первых байтов
        iv = encrypted_data[:len(key)]
        encrypted_bytes = encrypted_data[len(key):]
        
        # Применяем XOR к каждому байту зашифрованного текста с ключом и IV
        decrypted_bytes = bytearray(
            encrypted_bytes[i] ^ key[i % len(key)] ^ iv[i % len(iv)] for i in range(len(encrypted_bytes))
        )
        return decrypted_bytes.decode('utf-8')
    except (base64.binascii.Error, ValueError) as e:
        raise EncryptionError(f"Ошибка при декодировании сообщения: {e}")
    except Exception as e:
        raise EncryptionError(f"Ошибка при дешифровании сообщения: {e}")
