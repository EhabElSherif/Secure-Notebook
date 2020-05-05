import tkinter as tk
from tkinter import messagebox
import pygubu
from enc_dec import encrypt,decrypt

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
        
        # self.set_title("Secure Notebook")
        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)
        builder.connect_callbacks(self)

    def on_encbutton_clicked(self):
        self.inputFilePathValue = self.inputFilePath.cget('path')
        self.inputPasswordValue = self.passwordEntry.get()

        if not (self.inputFilePathValue and self.inputPasswordValue ):
            messagebox.showerror("Insufficient Parameters","Make sure to enter the file path AND your password")
            return

        print("Input Path:",self.inputFilePathValue)
        print("Input Password:",self.inputPasswordValue)
        response = encrypt(self.inputFilePathValue,self.inputPasswordValue)
        if response["error"]:
            messagebox.showerror(response["title"],response["msg"])
        else:
            messagebox.showinfo(response["title"],response["msg"])


    def on_decbutton_clicked(self):
        self.inputFilePathValue = self.inputFilePath.cget('path')
        self.inputPasswordValue = self.passwordEntry.get()

        if not (self.inputFilePathValue and self.inputPasswordValue ):
            messagebox.showerror("Insufficient Parameters","Make sure to enter the file path AND your password")
            return
            
        print("Input Path:",self.inputFilePathValue)
        print("Input Password:",self.inputPasswordValue)
        response = decrypt(self.inputFilePathValue,self.inputPasswordValue)
        if response["error"]:
            messagebox.showerror(response["title"],response["msg"])
        else:
            messagebox.showinfo(response["title"],response["msg"])


    def run(self):
        self.mainwindow.mainloop()


if __name__ == '__main__':
    root = tk.Tk()
    root.title("Secure Notebook")
    app = SecureNotebook(root)
    root.mainloop()