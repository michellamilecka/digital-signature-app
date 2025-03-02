import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import json
import getpass
import base64
import datetime
import os

jsonPath = "kluczePubliczne.json"  # ścieżka do pliku JSON
private_key_path = "private.pem"
public_key_path = "public.pem"

def getUsername():
    username = getpass.getuser()
    return username


def addUserToJson(username, public_key):
    try:
        with open(jsonPath, 'a+') as file:
            file.seek(0)
            users_data = json.load(file)
    except json.decoder.JSONDecodeError:
        users_data = []

    for user in users_data:
        if user['Username'] == username:
            return False

    # Zamiana klucza publicznego na base64
    public_key_base64 = base64.b64encode(public_key).decode('utf-8')

    new_user = {'Username': username, 'Public_Key': public_key_base64}
    users_data.append(new_user)

    with open(jsonPath, 'w') as file:
        json.dump(users_data, file, indent=4)

    return True


####################################################################
def getPublicKeyByUsername(username):
    try:
        with open(jsonPath, 'r') as file:
            users_data = json.load(file)
        for user in users_data:
            if user['Username'] == username:
                public_key_base64 = user['Public_Key']
                return base64.b64decode(public_key_base64)
    except json.decoder.JSONDecodeError:
        pass
    return None

def createKeys():
    username = getUsername()
    public_key = getPublicKeyByUsername(username)
    
    if public_key is None:
        # User not found, generate both keys
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save the private key to a file
        with open(private_key_path, 'wb') as file:
            file.write(private_key)
        # Save the public key to a file
        with open(public_key_path, 'wb') as file:
            file.write(public_key)
        
        # Save public key to kluczePubliczne.json
        if addUserToJson(username, public_key):
            print("Dodano nowego użytkownika do pliku JSON.")
        else:
            print("Użytkownik już istnieje w pliku JSON.")  
    else:
        # User found, load keys from files
        with open(private_key_path, 'rb') as file:
            private_key = file.read()
        with open(public_key_path, 'rb') as file:
            public_key = file.read()

    return private_key, public_key


def calculateSHA256(file_path):
    # otwieramy plik do odczytu w trybie binarnym
    with open(file_path, 'rb') as file:
        # wczytujemy cały plik do pamięci
        file_data = file.read()

        # tworzymy obiekt hashujący SHA-256
    sha256_hash = SHA256.new(file_data)
    return sha256_hash


def createSignature(private_key_path, file_hash):
    # wczytujemy klucz prywatny
    private_key = RSA.import_key(open(private_key_path).read())
    # tworzymy obiekt podpisujący PKCS#1 v1.5 na podstawie klucza prywatnego
    signer = pkcs1_15.new(private_key)
    # podpisujemy przekazany skrót za pomocą klucza prywatnego i algorytmu PKCS#1 v1.5
    signature = signer.sign(file_hash)
    return signature


def saveSignature(signature, signature_path):
    with open(signature_path, 'wb') as file:
        file.write(signature)


def generateMetadata(file_path):
    # nazwa użytkownika
    username = getUsername()
    # data podpisania (generacji metadanych
    date_signed = str(datetime.datetime.now())
    # rozmiar pliku w bajtach
    file_size = os.path.getsize(file_path)
    # typ algorytmu
    algorithm = 'RSA'
    metadata = {
        'file_name': file_path.split('/')[-1],
        'username': username,
        'date_signed': date_signed,
        'file_size': file_size,
        'algorithm': algorithm
    }
    return metadata


def saveMetadata(metadata, file_path):
    with open(file_path, 'w') as file:
        json.dump(metadata, file, indent=4)


def signFile(file_path):
    private_key, public_key = createKeys()
    file_hash = calculateSHA256(file_path)
    signature = createSignature(private_key_path, file_hash)

    if '.' in file_path:
        file_path_without_extension = file_path[:file_path.rfind('.')]
    else:
        file_path_without_extension = file_path
    file_name = file_path_without_extension + '.p7s'
    metadata_name = file_path_without_extension + '.json'

    saveSignature(signature, file_name)
    metadata = generateMetadata(file_path)
    saveMetadata(metadata, metadata_name)

    result_label.config(text="Plik został podpisany.")


def loadSignature(signature_path):
    with open(signature_path, 'rb') as file:
        signature = file.read()
    return signature


def loadMetadata(metadata_path):
    with open(metadata_path, 'r') as file:
        metadata = json.load(file)
    return metadata

def getPublicKeyByUsername(username):
    with open(jsonPath, 'r') as file:
        users_data = json.load(file)
    for user in users_data:
        if user['Username'] == username:
            public_key_base64 = user['Public_Key']
            return base64.b64decode(public_key_base64)
    return None


def verifySignature(signature_path, selected_file_path):
    signature = loadSignature(signature_path)
    file_hash = calculateSHA256(selected_file_path)

    # Wczytujemy klucz publiczny
    if selected_file_path and signature_path:
        username = simpledialog.askstring("Nazwa użytkownika", "Podaj nazwę użytkownika:")
        if username:
            key_from_json = getPublicKeyByUsername(username)
            if key_from_json is None:
                result_label.config(text="Podano niepoprawnego użytkownika.")
                return False
        else:
            result_label.config(text="Nie podano nazwy użytkownika.")
            return False

    public_key = RSA.import_key(key_from_json)
    # Tworzymy obiekt weryfikujący PKCS#1 v1.5 na podstawie klucza publicznego
    verifier = pkcs1_15.new(public_key)
    try:
        # Weryfikujemy podpis dla przekazanego skrótu
        verifier.verify(file_hash, signature)
        result_label.config(text="Podpis jest prawidłowy.")
        return True
    except (ValueError, TypeError):
        result_label.config(text="Podpis jest nieprawidłowy.")
        return False


def reset_view():
    for widget in mainframe.winfo_children():
        widget.pack_forget()
    file_label.config(text="")
    signature_file_label.config(text="")
    result_label.config(text="")


def show_main_options():
    mode_label.pack(expand=True, fill="x")
    sign_mode_button.pack(expand=True, fill="x")
    verify_mode_button.pack(expand=True, fill="x")


def show_sign_options():
    reset_view()
    file_label.pack(expand=True, fill="x")
    select_file_button.pack(expand=True, fill="x")
    back_button.pack(expand=True, fill="x")
    result_label.pack(expand=True, fill="x")
    mode.set('sign')


def show_verify_options():
    reset_view()
    file_label.pack(expand=True, fill="x")
    select_file_button.pack(expand=True, fill="x")
    signature_file_label.pack(expand=True, fill="x")
    select_signature_file_button.pack(expand=True, fill="x")
    back_button.pack(expand=True, fill="x")
    mode.set('verify')


def back_to_main():
    reset_view()
    show_main_options()


def select_file(file_label, filetypes):
    # Open file dialog and get the selected file path
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    if file_path:
        global selected_file_path
        selected_file_path = file_path
        file_label.config(text=file_path)
        check_buttons()


def select_signature(file_label, filetypes):
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    if file_path:
        global selected_signature_path
        selected_signature_path = file_path
        file_label.config(text=file_path)
        check_buttons()


def check_buttons():
    if mode.get() == 'sign':
        if file_label.cget("text"):
            sign_button.pack(expand=True, fill="x")
        else:
            sign_button.pack_forget()
    elif mode.get() == 'verify':
        if file_label.cget("text") and signature_file_label.cget("text"):
            verify_button.pack(expand=True, fill="x")
            result_label.pack(expand=True, fill="x")
        else:
            verify_button.pack_forget()


root = tk.Tk()
root.title("Aplikacja Podpisów Cyfrowych")
root.geometry("400x300")
# Tworzenie stylu dla widżetów ttk
style = ttk.Style()
style.configure('TFrame', background='pink')
style.configure('TLabel', background='pink')
style.configure('Button', background='lightpink')

mainframe = ttk.Frame(root, padding="20")
mainframe.pack(expand=True, fill="both")

mode = tk.StringVar()

mode_label = ttk.Label(mainframe, text="Wybierz tryb:")
mode_label.pack(expand=True, fill="x")

sign_mode_button = ttk.Button(mainframe, text="Podpisz plik", command=show_sign_options)
sign_mode_button.pack(expand=True, fill="x")

verify_mode_button = ttk.Button(mainframe, text="Zweryfikuj podpis", command=show_verify_options)
verify_mode_button.pack(expand=True, fill="x")

file_label = ttk.Label(mainframe, text="")
signature_file_label = ttk.Label(mainframe, text="")

select_file_button = ttk.Button(mainframe, text="Wybierz plik", command=lambda: select_file(file_label, filetypes=[
    ("Wszystkie pliki", "*.*"),
    ("Pliki tekstowe", "*.txt"),
    ("Dokumenty PDF", "*.pdf"),
    ("Dokumenty Word", "*.doc *.docx"),
    ("Dokumenty Excel", "*.xls *.xlsx"),
    ("Obrazy", "*.jpg *.jpeg *.png *.gif *.bmp"),
    ("Dźwięki", "*.wav *.mp3 *.ogg *.flac"),
    ("Filmy", "*.avi *.mp4 *.mkv *.mov"),
    ("Pliki ZIP", "*.zip *.rar *.7z"),
    ("Pliki HTML", "*.html *.htm"),
    ("Pliki XML", "*.xml *.xsd"),
    ("Wszystkie pliki", "*.*"),
]))

select_signature_file_button = ttk.Button(mainframe, text="Wybierz plik z podpisem",
                                          command=lambda: select_signature(signature_file_label,
                                                                           filetypes=[("Pliki podpisu", "*.p7s")]))

sign_button = ttk.Button(mainframe, text="Podpisz plik", command=lambda: signFile(selected_file_path))
verify_button = ttk.Button(mainframe, text="Zweryfikuj podpis",
                           command=lambda: verifySignature(selected_signature_path, selected_file_path))
back_button = ttk.Button(mainframe, text="Powrót", command=back_to_main)

result_label = ttk.Label(mainframe, text="")

root.mainloop()