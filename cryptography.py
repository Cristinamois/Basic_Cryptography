import tkinter as tk
from tkinter import ttk, messagebox

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26 + base
            result += chr(shifted)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    key_len = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            k = ord(key[key_index % key_len]) - ord('a')
            shifted = (ord(char) - base + k) % 26 + base
            result += chr(shifted)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    key_len = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            k = ord(key[key_index % key_len]) - ord('a')
            shifted = (ord(char) - base - k) % 26 + base
            result += chr(shifted)
            key_index += 1
        else:
            result += char
    return result

def run():
    root = tk.Tk()
    root.title("Cryptographie Simple")

    # Style global
    style = ttk.Style(root)
    style.theme_use('clam')  # thème clair, moderne
    style.configure("TFrame", background="#c4c4c4")
    style.configure("TLabel", background="#b3b3b3", font=("Segoe UI", 11))
    style.configure("TButton",
                    font=("Segoe UI Semibold", 11),
                    padding=6,
                    background="#0a2f58",
                    foreground="white")
    style.map("TButton",
              background=[("active", "#11375C")])
    style.configure("TCombobox", padding=5)
    style.configure("TEntry", padding=5)

    frm = ttk.Frame(root, padding=20)
    frm.grid(sticky="nsew")

    # Variables
    method_var = tk.StringVar(value="César")
    action_var = tk.StringVar(value="Chiffrer")

    # Widgets
    ttk.Label(frm, text="Méthode :").grid(column=0, row=0, sticky="w", pady=6)
    method_cb = ttk.Combobox(frm, textvariable=method_var, values=["César", "Vigenère"], state="readonly", width=15)
    method_cb.grid(column=1, row=0, sticky="ew", pady=6)

    ttk.Label(frm, text="Texte :").grid(column=0, row=1, sticky="nw", pady=6)
    text_entry = tk.Text(frm, width=45, height=6, font=("Consolas", 11), wrap="word", relief="solid", borderwidth=1)
    text_entry.grid(column=1, row=1, sticky="ew", pady=6)

    ttk.Label(frm, text="Décalage (César) :").grid(column=0, row=2, sticky="w", pady=6)
    shift_entry = ttk.Entry(frm)
    shift_entry.grid(column=1, row=2, sticky="ew", pady=6)
    shift_entry.insert(0, "3")

    ttk.Label(frm, text="Clé (Vigenère) :").grid(column=0, row=3, sticky="w", pady=6)
    key_entry = ttk.Entry(frm)
    key_entry.grid(column=1, row=3, sticky="ew", pady=6)

    ttk.Label(frm, text="Action :").grid(column=0, row=4, sticky="w", pady=6)
    action_cb = ttk.Combobox(frm, textvariable=action_var, values=["Chiffrer", "Déchiffrer"], state="readonly", width=15)
    action_cb.grid(column=1, row=4, sticky="ew", pady=6)

    btn = ttk.Button(frm, text="Exécuter")
    btn.grid(column=0, row=5, columnspan=2, pady=15, sticky="ew")

    # Ligne de séparation
    separator = ttk.Separator(frm, orient='horizontal')
    separator.grid(column=0, row=6, columnspan=2, sticky="ew", pady=10)

    ttk.Label(frm, text="Résultat :").grid(column=0, row=7, sticky="nw", pady=6)
    result_text = tk.Text(frm, width=45, height=6, font=("Consolas", 11), wrap="word", relief="solid", borderwidth=1, state="normal")
    result_text.grid(column=1, row=7, sticky="ew", pady=6)

    # Label de feedback simple
    feedback_label = ttk.Label(frm, text="", foreground="red", font=("Segoe UI", 10, "italic"))
    feedback_label.grid(column=0, row=8, columnspan=2)

    # Fonction pour activer/désactiver champs selon méthode
    def update_fields(event=None):
        if method_var.get() == "César":
            shift_entry.configure(state="normal")
            key_entry.configure(state="disabled")
            key_entry.delete(0, tk.END)
        else:
            shift_entry.configure(state="disabled")
            shift_entry.delete(0, tk.END)
            key_entry.configure(state="normal")
        feedback_label.config(text="")

    method_cb.bind("<<ComboboxSelected>>", update_fields)
    update_fields()

    # Fonction de traitement
    def process():
        feedback_label.config(text="")
        method = method_var.get()
        action = action_var.get()
        text = text_entry.get("1.0", tk.END).strip()
        if not text:
            feedback_label.config(text="Veuillez entrer un texte.")
            return
        if method == "César":
            try:
                shift = int(shift_entry.get())
            except ValueError:
                feedback_label.config(text="Le décalage doit être un entier.")
                return
            if action == "Chiffrer":
                res = caesar_encrypt(text, shift)
            else:
                res = caesar_decrypt(text, shift)
        else:  # Vigenère
            key = key_entry.get()
            if not key.isalpha():
                feedback_label.config(text="La clé doit contenir uniquement des lettres.")
                return
            if action == "Chiffrer":
                res = vigenere_encrypt(text, key)
            else:
                res = vigenere_decrypt(text, key)
        result_text.configure(state="normal")
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, res)
        result_text.configure(state="disabled")

    btn.config(command=process)

    # Configurations de poids pour responsive
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    frm.columnconfigure(1, weight=1)

    root.mainloop()

if __name__ == "__main__":
    run()
