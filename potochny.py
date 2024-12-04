import tkinter as tk
from tkinter import messagebox

# S-блоки и вспомогательные функции
S_BOX = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]

def replacing(value):
    output = 0
    for i in range(8):
        nbl = (value >> (4 * i)) & 0xF
        output |= S_BOX[i][nbl] << (4 * i)
    return output

def feistel(left, right, key):
    tmp = (left + key) % (2 ** 32)
    tmp = replacing(tmp)
    tmp = (tmp << 11) | (tmp >> 21)
    tmp = tmp & 0xFFFFFFFF
    return right ^ tmp

def encrypt_block(block, keys):
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    for i in range(24):
        left, right = feistel(left, right, keys[i % 8]), left
    for i in range(8):
        left, right = feistel(left, right, keys[7 - i]), left
    return (right << 32) | left

def decrypt_block(block, keys):
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    for i in range(8):
        left, right = feistel(left, right, keys[i]), left
    for i in range(24):
        left, right = feistel(left, right, keys[7 - (i % 8)]), left
    return (right << 32) | left

def gost_stream_cipher(data, key):
    keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    stream = b""
    count = 0

    for i in range(0, len(data), 8):
        # Генерируем блок шифра
        keystream_block = encrypt_block(count, keys)
        count += 1
        keystream = keystream_block.to_bytes(8, 'big')

        dt = data[i:i + 8]
        stream += bytes([b ^ k for b, k in zip(dt, keystream)])

    return stream

# Интерфейс
def encrypt_gost_stream():
    text = plaintext_entry.get()
    key = key_entry.get()
    if text and key:
            key = int(key, 16)
            data = text.encode('utf-8')
            encrypted = gost_stream_cipher(data, key)
            encrypted_hex = encrypted.hex()

            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Зашифрованный текст: {encrypted_hex}")
    else:
        messagebox.showwarning("Ошибка", "введи текст и ключ.")

def decrypt_gost_stream():
    text = ciphertext_entry.get()
    key = key_entry.get()
    if text and key:
            key = int(key, 16)
            data = bytes.fromhex(text)
            decrypted = gost_stream_cipher(data, key)
            decrypted_text = decrypted.decode('utf-8')

            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Расшифрованный текст: {decrypted_text}")
    else:
        messagebox.showwarning("Ошибка", "введи текст и ключ.")

# Главное окно
root = tk.Tk()
root.title("Поточный шифр ГОСТ")

tk.Label(root, text="Исходный текст:").grid(row=0, column=0, padx=10, pady=10)
plaintext_entry = tk.Entry(root, width=40)
plaintext_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Ключ:").grid(row=1, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, width=40)
key_entry.grid(row=1, column=1, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Зашифровать", command=encrypt_gost_stream)
encrypt_button.grid(row=2, column=0, padx=10, pady=10)

tk.Label(root, text="Зашифрованный текст:").grid(row=3, column=0, padx=10, pady=10)
ciphertext_entry = tk.Entry(root, width=40)
ciphertext_entry.grid(row=3, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Расшифровать", command=decrypt_gost_stream)
decrypt_button.grid(row=4, column=0, padx=10, pady=10)

tk.Label(root, text="Результат:").grid(row=5, column=0, padx=10, pady=10)
result_text = tk.Text(root, height=5, width=40)
result_text.grid(row=5, column=1, padx=10, pady=10)

root.mainloop()