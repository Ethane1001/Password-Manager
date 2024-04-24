#!/usr/bin/env python
# coding: utf-8

# In[1]:


import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import os

class PasswordManagerSetup:
    def __init__(self, master):
        self.master = master
        self.master.title("Master Password Setup")

        self.label_master_password = tk.Label(master, text="Set Master Password:")
        self.label_master_password.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.entry_master_password = tk.Entry(master, show="*")
        self.entry_master_password.grid(row=0, column=1, padx=10, pady=5)

        self.button_create = tk.Button(master, text="Create", command=self.create_master_password)
        self.button_create.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

    def generate_key(self):
        if not os.path.exists("master_key.key"):
            key = Fernet.generate_key()
            with open("master_key.key", "wb") as key_file:
                key_file.write(key)

    def encrypt_password(self, password):
        key = self.load_key()
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return encrypted_password

    def create_master_password(self):
        master_password = self.entry_master_password.get()
        if master_password:
            self.generate_key()
            encrypted_password = self.encrypt_password(master_password)
            with open("master_password.txt", "wb") as f:
                f.write(encrypted_password)
            self.master.destroy()
            messagebox.showinfo("Success", "Master password set successfully!")
        else:
            messagebox.showerror("Error", "Please enter a master password.")

    def load_key(self):
        return open("master_key.key", "rb").read()

class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.label_master_password = tk.Label(master, text="Master Password:")
        self.label_master_password.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.entry_master_password = tk.Entry(master, show="*")
        self.entry_master_password.grid(row=0, column=1, padx=10, pady=5)

        self.button_login = tk.Button(master, text="Login", command=self.login)
        self.button_login.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

    def load_key(self):
        return open("master_key.key", "rb").read()

    def decrypt_password(self, encrypted_password):
        key = self.load_key()
        cipher_suite = Fernet(key)
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
        return decrypted_password

    def verify_master_password(self, entered_password):
        try:
            with open("master_password.txt", "rb") as f:
                master_password = f.read()
            decrypted_password = self.decrypt_password(master_password)
            return entered_password == decrypted_password
        except FileNotFoundError:
            return False

    def login(self):
        entered_password = self.entry_master_password.get()
        if self.verify_master_password(entered_password):
            self.master.destroy()
            self.show_password_manager()
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def show_password_manager(self):
        root = tk.Tk()
        app = PasswordManagerApp(root)
        root.mainloop()

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.label_service = tk.Label(master, text="Service:")
        self.label_service.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.label_username = tk.Label(master, text="Username:")
        self.label_username.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.label_password = tk.Label(master, text="Password:")
        self.label_password.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.entry_service = tk.Entry(master)
        self.entry_service.grid(row=0, column=1, padx=10, pady=5)

        self.entry_username = tk.Entry(master)
        self.entry_username.grid(row=1, column=1, padx=10, pady=5)

        self.entry_password = tk.Entry(master, show="*")
        self.entry_password.grid(row=2, column=1, padx=10, pady=5)

        self.button_save = tk.Button(master, text="Save Credentials", command=self.save_credentials)
        self.button_save.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

        self.button_retrieve = tk.Button(master, text="Retrieve Credentials", command=self.retrieve_credentials)
        self.button_retrieve.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

    def generate_key(self):
        if not os.path.exists("key.key"):
            key = Fernet.generate_key()
            with open("key.key", "wb") as key_file:
                key_file.write(key)

    def load_key(self):
        return open("key.key", "rb").read()

    def encrypt_data(self, data):
        self.generate_key()
        key = self.load_key()
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        key = self.load_key()
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data

    def save_credentials(self):
        service = self.entry_service.get()
        username = self.entry_username.get()
        password = self.entry_password.get()

        if service and username and password:
            encrypted_username = self.encrypt_data(username)
            encrypted_password = self.encrypt_data(password)
            with open("credentials.txt", "a") as f:
                f.write(f"{service}: {encrypted_username.decode()} | {encrypted_password.decode()}\n")
            messagebox.showinfo("Success", "Credentials saved successfully!")
        else:
            messagebox.showerror("Error", "Please enter service, username, and password.")

    def retrieve_credentials(self):
        service = self.entry_service.get()

        if service:
            try:
                with open("credentials.txt", "r") as f:
                    lines = f.readlines()
                    for line in lines:
                        if service in line:
                            encrypted_username, encrypted_password = line.split(": ")[1].split(" | ")
                            decrypted_username = self.decrypt_data(encrypted_username.encode())
                            decrypted_password = self.decrypt_data(encrypted_password.encode())
                            messagebox.showinfo("Credentials", f"Username: {decrypted_username}\nPassword: {decrypted_password}")
                            break
                    else:
                        messagebox.showerror("Error", f"No credentials found for {service}")
            except FileNotFoundError:
                messagebox.showerror("Error", "No credentials saved yet.")
        else:
            messagebox.showerror("Error", "Please enter a service.")

def main():
    if not os.path.exists("master_password.txt"):
        root = tk.Tk()
        app = PasswordManagerSetup(root)
        root.mainloop()
    else:
        root = tk.Tk()
        app = PasswordManager(root)
        root.mainloop()

if __name__ == "__main__":
    main()


# In[ ]:





# In[ ]:




