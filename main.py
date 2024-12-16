from crypto_utils import encrypt, decrypt

# Сообщение для шифрования
message = "Hello World!"

# Шифруем сообщение
encrypted_message = encrypt(message)
print(f"Encrypted: {encrypted_message}")

# Расшифровываем сообщение
decrypted_message = decrypt(encrypted_message)
print(f"Decrypted: {decrypted_message}")
