import sqlite3, hashlib
from sqlite3.dbapi2 import Cursor
from tkinter import *


#DATABASE
with sqlite3.connect("pw.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpw(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL); 
""")


window = Tk()
window.title("Password Manager")


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def firstScreen():
    window.geometry("250x140")

    lbl = Label(window, text="Create Master Password")
    lbl.pack()

    txt = Entry(window, width=20, show="*", fg="blue")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter password")
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*", fg="blue")
    txt1.pack()

    lbl2 = Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():

            hashedpw = hashPassword(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpw(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedpw)])
            db.commit()

            passwordVault()
        else: 
            lbl2.config(text="Passwords do not match", fg="red")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)


def loginScreen():
    window.geometry("250x100")

    lbl = Label(window, text="Enter Master Password")
    lbl.pack()

    txt = Entry(window, width=20, show="*", fg="blue")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkhashpw = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpw WHERE id = 1 AND password = ?", [(checkhashpw)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else: 
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password", fg="red")
        

    btn = Button(window, text="Login", command=checkPassword)
    btn.pack(pady=5)



def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x400")

    lbl = Label(window, text="Password Vault")
    lbl.pack()

cursor.execute("SELECT * FROM masterpw")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()