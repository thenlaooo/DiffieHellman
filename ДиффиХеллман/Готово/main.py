import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64

class DiffieHellmanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифрование и дешифрование с Diffie-Hellman")
        
        # Параметры Diffie-Hellman
        self.p_label = tk.Label(root, text="p (простое число):")
        self.p_label.pack()
        self.p_entry = tk.Entry(root)
        self.p_entry.pack()
        
        self.g_label = tk.Label(root, text="g (генератор):")
        self.g_label.pack()
        self.g_entry = tk.Entry(root)
        self.g_entry.pack()
        
        # Кнопка для автоматической генерации
        self.auto_generate_button = tk.Button(root, text="Сгенерировать p и g автоматически", command=self.auto_generate_p_g)
        self.auto_generate_button.pack()
        
        # Кнопка для генерации ключей
        self.generate_button = tk.Button(root, text="Сгенерировать ключи", command=self.generate_keys)
        self.generate_button.pack()
        
        # Поле для ввода сообщения
        self.message_label = tk.Label(root, text="Введите сообщение:")
        self.message_label.pack()
        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack()
        
        # Новое поле для зашифрованного сообщения
        self.encrypted_label = tk.Label(root, text="Введите зашифрованное сообщение:")
        self.encrypted_label.pack()
        self.encrypted_text = scrolledtext.ScrolledText(root, width=60, height=5)
        self.encrypted_text.pack()
        
        # Кнопки для шифрования, копирования и вставки
        self.encrypt_button = tk.Button(root, text="Зашифровать", command=self.encrypt_message)
        self.encrypt_button.pack()
        
        self.copy_button = tk.Button(root, text="Скопировать зашифрованное сообщение", command=self.copy_encrypted_message)
        self.copy_button.pack()
        
        self.paste_button = tk.Button(root, text="Вставить из буфера", command=self.paste_from_clipboard)
        self.paste_button.pack()
        
        self.decrypt_button = tk.Button(root, text="Расшифровать", command=self.decrypt_message)
        self.decrypt_button.pack()
        
        # Вывод результатов
        self.output_text = scrolledtext.ScrolledText(root, width=60, height=10)
        self.output_text.pack()
        
        # Внутренние переменные
        self.alice_private_key = None
        self.bob_private_key = None
        self.shared_key_alice = None
        self.shared_key_bob = None
        self.fernet_key = None
        self.generated_parameters = None
        self.last_encrypted_message = None  # Новая переменная для хранения зашифрованного сообщения

    def auto_generate_p_g(self):
        try:
            self.generated_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            p = self.generated_parameters.parameter_numbers().p
            g = self.generated_parameters.parameter_numbers().g
            
            self.p_entry.delete(0, tk.END)
            self.p_entry.insert(0, str(p))
            self.g_entry.delete(0, tk.END)
            self.g_entry.insert(0, str(g))
            self.output_text.insert(tk.END, f"Автоматически сгенерировано: p = {p}, g = {g}\n")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации p и g: {str(e)}. Убедитесь, что библиотека cryptography установлена.")

    def generate_keys(self):
        try:
            if self.generated_parameters is None:
                p = int(self.p_entry.get())
                g = int(self.g_entry.get())
                self.generated_parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
            
            self.alice_private_key = self.generated_parameters.generate_private_key()
            self.bob_private_key = self.generated_parameters.generate_private_key()
            
            alice_public_key = self.alice_private_key.public_key()
            bob_public_key = self.bob_private_key.public_key()
            
            self.shared_key_alice = self.alice_private_key.exchange(bob_public_key)
            self.shared_key_bob = self.bob_private_key.exchange(alice_public_key)
            
            self.fernet_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                info=b'handshake data',
                backend=default_backend()
            ).derive(self.shared_key_alice)
            
            self.output_text.insert(tk.END, "Ключи успешно сгенерированы и обменены!\n")
        
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректные значения p или g. Убедитесь, что они сгенерированы автоматически.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации ключей: {str(e)}")

    def encrypt_message(self):
        if self.fernet_key is None:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи!")
            return
        
        message = self.message_entry.get().encode()
        fernet = Fernet(base64.urlsafe_b64encode(self.fernet_key))
        encrypted_message = fernet.encrypt(message).decode()  # Декодируем для хранения как строки
        
        self.last_encrypted_message = encrypted_message  # Сохраняем только зашифрованное сообщение
        self.output_text.insert(tk.END, f"Зашифрованное сообщение: {encrypted_message}\n")  # Выводим в поле
    
    def copy_encrypted_message(self):
        if self.last_encrypted_message:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.last_encrypted_message)  # Копируем только зашифрованное сообщение
            self.root.update()
            messagebox.showinfo("Скопировано", "Зашифрованное сообщение скопировано в буфер обмена!")
        else:
            messagebox.showwarning("Предупреждение", "Нет зашифрованного сообщения для копирования.")
    
    def paste_from_clipboard(self):
        try:
            pasted_text = self.root.clipboard_get()
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, pasted_text)
            messagebox.showinfo("Вставлено", "Текст вставлен из буфера обмена!")
        except tk.TclError:
            messagebox.showerror("Ошибка", "Буфер обмена пуст или недоступен.")
    
    def decrypt_message(self):
        if self.fernet_key is None:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи!")
            return
        
        encrypted_text = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_text:
            messagebox.showerror("Ошибка", "Введите зашифрованное сообщение для дешифрования.")
            return
        
        try:
            fernet = Fernet(base64.urlsafe_b64encode(self.fernet_key))
            decrypted_message = fernet.decrypt(encrypted_text.encode())
            self.output_text.insert(tk.END, f"Расшифрованное сообщение: {decrypted_message.decode()}\n")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DiffieHellmanApp(root)
    root.mainloop()