import tkinter as tk
from tkinter import messagebox
import pygubu
from enc_dec import encrypt,decrypt,calculate_hmac,write_ciphertext,read_ciphertext
from base64 import b64decode, b64encode
from time import sleep

class SecureNotebook(pygubu.TkApplication):

    def __init__(self,master):

        self.inputFilePathValue = None
        self.inputPasswordValue = None
        
        #1: Create a builder
        self.builder = builder = pygubu.Builder()

        #2: Load an ui file
        builder.add_from_file('mainwindow.ui')

        #3: Create the mainwindow
        self.mainwindow = builder.get_object('mainwindow',master)
        self.inputFilePath = builder.get_object('inputFilePath')
        self.passwordEntry = builder.get_object('PasswordEntry')
        self.progressLbl = builder.get_object('ProgressLbl')
        
        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)
        builder.connect_callbacks(self)

    def on_encbutton_clicked(self):
        self.inputFilePathValue = self.inputFilePath.cget('path')
        self.inputPasswordValue = self.passwordEntry.get()

        if not (self.inputFilePathValue and self.inputPasswordValue ):
            messagebox.showerror("Insufficient Parameters","Make sure to enter the file path AND your password")
            return
            
        self.progressLbl["text"]="Encrypting..."
        self.progressLbl.update()
        sleep(1)

        response = encrypt(self.inputFilePathValue,self.inputPasswordValue)
        
        if response["error"]:
            messagebox.showerror(response["title"],response["msg"])
            self.progressLbl["text"]=""
            self.progressLbl.update()
            return

        self.progressLbl["text"]="Encryption is completed..."
        self.progressLbl.update()
        sleep(1)

        self.progressLbl["text"]="Calculating HMAC..."
        self.progressLbl.update()
        sleep(1)

        hmac = calculate_hmac(response["ct"])

        self.progressLbl["text"]="Appending HMAC..."
        self.progressLbl.update()
        sleep(1)

        response = write_ciphertext(self.inputFilePathValue,response["key"],response["nonce"],response["ct"],hmac)
        
        self.progressLbl["text"]="Done..."
        self.progressLbl.update()

        if not response["error"]:
            messagebox.showinfo(response["title"],response["msg"])
            self.progressLbl["text"]=""
            self.progressLbl.update()


    def on_decbutton_clicked(self):
        self.inputFilePathValue = self.inputFilePath.cget('path')
        self.inputPasswordValue = self.passwordEntry.get()

        if not (self.inputFilePathValue and self.inputPasswordValue ):
            messagebox.showerror("Insufficient Parameters","Make sure to enter the file path AND your password")
            return

        self.progressLbl["text"]="Validating password..."
        self.progressLbl.update()
        sleep(1)

        response = read_ciphertext(self.inputFilePathValue,self.inputPasswordValue)
        if response["error"]:
            messagebox.showerror(response["title"],response["msg"])
            self.progressLbl["text"]=""
            self.progressLbl.update()
            return
        
        self.progressLbl["text"]="Verifying HMAC..."
        self.progressLbl.update()
        sleep(1)

        inputHMAC = calculate_hmac(response["ct"])
        if not(inputHMAC == response["hmac"]):
            self.progressLbl["text"]=""
            self.progressLbl.update()
            messagebox.showerror("Changed File","The encrypted file has been changed")
            return
            
        self.progressLbl["text"]="Decrypting..."
        self.progressLbl.update()
        sleep(1)
        decrypt(self.inputFilePathValue,response["key"],response["nonce"],response["ct"])

        self.progressLbl["text"]="Decryption is completed..."
        self.progressLbl.update()
        sleep(1)
        self.progressLbl["text"]=""
        self.progressLbl.update()


    def run(self):
        self.mainwindow.mainloop()


if __name__ == '__main__':
    root = tk.Tk()
    root.title("Secure Notebook")
    app = SecureNotebook(root)
    root.mainloop()