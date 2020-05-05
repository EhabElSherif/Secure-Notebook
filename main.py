import tkinter as tk
from tkinter import messagebox
import pygubu


class SecureNotebook:

    def __init__(self,master):

        #1: Create a builder
        self.builder = builder = pygubu.Builder()

        #2: Load an ui file
        builder.add_from_file('mainwindow.ui')

        #3: Create the mainwindow
        self.mainwindow = builder.get_object('mainwindow',master)
        self.filepath = builder.get_object('inputFilePath')
        self.filepath = builder.get_object('PasswordEntry')
        self.filepath = builder.get_object('EncButton')
        self.filepath = builder.get_object('DecButton')

        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)

        builder.connect_callbacks(self)

    def on_path_changed(self, event=None):
        path = self.filepath.cget('path')

    def run(self):
        self.mainwindow.mainloop()


if __name__ == '__main__':
    root = tk.Tk()
    app = SecureNotebook(root)
    root.mainloop()