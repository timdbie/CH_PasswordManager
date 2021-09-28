import secrets, string, sqlite3, hashlib, os, pyperclip
import tkinter as tk
from tkinter import ttk
from tkinter import *
#from PIL import ImageTk, Image
from urllib.parse import urlparse
from functools import partial

from requests.api import get, request

#base folder
base_folder = os.path.dirname(__file__)

#database code
with sqlite3.connect('pw.db') as db:
    cursor = db.cursor()

#scroll

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

#Create PopUp
def popUp():
    popUpWindow = Toplevel(window)
    popUpWindow.grab_set()
    popUpWindow.title("Add")
    popUpWindow.geometry("400x300")
    popUpWindow.config(bg="#4A4674")
    popUpWindow.resizable(False, False)
    popUpWindow.iconbitmap(icopath)

    def rngPassword():
        secure_str = ''.join((secrets.choice(string.ascii_letters + string.digits) for i in range(12)))
        txt3.delete(0,END)
        txt3.insert(0,secure_str)

    def addEntry():
        website = txt.get()
        username = txt2.get()
        password = txt3.get()

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        popUpWindow.destroy()
        vaultScreen()

    lbl = Label(popUpWindow, text="Website")
    lbl.config(anchor=W, fg="white", width=45, bg="#4A4674")
    lbl.pack(pady=(15,0))

    txt = Entry(popUpWindow, font=30)
    txt.pack(ipadx=50,ipady=5,pady=(0,10))
    txt.focus()

    lbl2 = Label(popUpWindow, text="Username")
    lbl2.config(anchor=W, fg="white", width=45, bg="#4A4674")
    lbl2.pack()
    
    txt2 = Entry(popUpWindow, font=30)
    txt2.pack(ipadx=50,ipady=5,pady=(0,10))

    lbl3 = Label(popUpWindow, text="Password")
    lbl3.config(anchor=W, fg="white", width=45, bg="#4A4674")
    lbl3.pack()

    txt3 = Entry(popUpWindow, font=30)
    txt3.pack(ipadx=143,ipady=5,pady=(0,10))

    btn3 = Button(txt3, command=rngPassword, text="RNG")
    btn3.pack(anchor=E, expand=YES)

    btn = Button(popUpWindow, command=addEntry, text="Add password", width=45, height=2, bg="green", fg="white", border=0)
    btn.pack(ipadx=1, pady=(20,0))


window = Tk()
window.update()

window.title("Password Manager")
window.config(bg="#4A4674")
window.resizable(False, False)

icopath = os.path.join(base_folder, "icon.ico")

window.iconbitmap(icopath)


def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1


def firstTimeScreen():
    window.geometry('600x400')
    
    header = Canvas(window, width=600, height=70, bg="#3C395F", highlightthickness=0)
    header.pack(fill=BOTH, expand=NO, pady=(0, 60))

    headertext = Label(header, text="Password Manager", fg="white", bg="#3C395F", font=60)
    headertext.pack(pady=20, padx=10, anchor=W)

    lbl = Label(window, text="Choose a Master Password")
    lbl.config(anchor=W, fg="white", width=45, bg="#4A4674")
    lbl.pack()

    txt = Entry(window, show="●", font=30)
    txt.pack(ipadx=45,ipady=5,pady=(0,10))
    txt.focus()

    lbl1 = Label(window, text="Re-enter password")
    lbl1.config(anchor=W, fg="white", width=45, bg="#4A4674")
    lbl1.pack()

    txt1 = Entry(window, show="●", font=30)
    txt1.pack(ipadx=45,ipady=5)

    lbl2 = Label(window, fg="red", bg="#4A4674")
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            vaultScreen()
        else:
            lbl2.config(text="Passwords do not match")

    btn = Button(window, text="Save Password", command=savePassword, width=44, height=2, bg="green", fg="white", border=0)
    btn.pack(pady=5)

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    header = Canvas(window, width=600, height=70, bg="#3C395F", highlightthickness=0)
    header.pack(fill=BOTH, expand=NO, pady=(0, 80))

    headertext = Label(header, text="Password Manager", fg="white", bg="#3C395F", font=60)
    headertext.pack(pady=20, padx=10, anchor=W)

    window.geometry('600x400')

    lbl = Label(window, text="Enter  Master Password")
    lbl.config(anchor=W, fg="white", width=45, bg="#4A4674")
    lbl.pack()

    txt = Entry(window, width=20, show="●", font=30)
    txt.pack(ipadx=45,ipady=5,pady=(0,10))
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER, fg="red", bg="#4A4674")
    lbl1.pack(side=TOP)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit", command=checkPassword, width=44, height=2, bg="green", fg="white", border=0)
    btn.pack(pady=5)


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    def editPopUp(input):
        id = input
        index = input - 1

        popUpWindow = Toplevel(window)
        popUpWindow.grab_set()
        popUpWindow.title("Edit")
        popUpWindow.geometry("400x300")
        popUpWindow.config(bg="#4A4674")
        popUpWindow.resizable(False, False)
        popUpWindow.iconbitmap(icopath)

        def editEntry():
            if(txt.get() != array[index][1]):
                cursor.execute('UPDATE vault SET website = ? WHERE id = ?', (txt.get(), id,))
                
            if(txt2.get() != array[index][2]):
                cursor.execute('UPDATE vault SET username = ? WHERE id = ?', (txt2.get(), id,))

            if(txt3.get() != array[index][3]):
                cursor.execute('UPDATE vault SET password = ? WHERE id = ?', (txt3.get(), id,))

            db.commit()
            popUpWindow.destroy()
            vaultScreen()

        lbl = Label(popUpWindow, text="Website")
        lbl.config(anchor=W, fg="white", width=45, bg="#4A4674")
        lbl.pack(pady=(15,0))

        txt = Entry(popUpWindow, font=30)
        txt.pack(ipadx=50,ipady=5,pady=(0,10))

        lbl2 = Label(popUpWindow, text="Website")
        lbl2.config(anchor=W, fg="white", width=45, bg="#4A4674")
        lbl2.pack()

        txt2 = Entry(popUpWindow, font=30)
        txt2.pack(ipadx=50,ipady=5,pady=(0,10))

        lbl3 = Label(popUpWindow, text="Website")
        lbl3.config(anchor=W, fg="white", width=45, bg="#4A4674")
        lbl3.pack()

        txt3 = Entry(popUpWindow, font=30)
        txt3.pack(ipadx=50,ipady=5,pady=(0,10))

        btn = Button(popUpWindow, command=editEntry, text="Edit", width=45, height=2, bg="green", fg="white", border=0)
        btn.pack(ipadx=1, pady=(20,0))

        cursor.execute('SELECT * FROM vault')
        if (cursor.fetchall() != None):
            cursor.execute('SELECT * FROM vault')

            array = cursor.fetchall()
            
            txt.insert(0, array[index][1])
            txt2.insert(0, array[index][2])
            txt3.insert(0, array[index][3])            
            
    window.geometry('800x400')
    window.resizable(height=None, width=None)

    headerframe = Frame(window, width=800, height=70, bg="#3C395F")
    headerframe.pack(fill=X)

    headertext = Label(headerframe, text="Password Manager", fg="white", bg="#3C395F", font=60)
    headertext.grid(pady=20, padx=10, row=0, column=0)

    headerbtn = Button(headerframe, text="ADD", fg="white", bg="green", border=0, command=popUp)
    headerbtn.grid(pady=20, padx=(0,25), ipadx=5, ipady=5, row=0, column=3, sticky=E)

    lbl = Label(headerframe, text="Website", relief=RAISED, width=28, anchor=W, bg="#3C395F", fg="white")
    lbl.grid(row=1, column=0)
    lbl = Label(headerframe, text="Username", relief=RAISED, width=28, anchor=W, bg="#3C395F", fg="white")
    lbl.grid(row=1, column=1)
    lbl = Label(headerframe, text="Password", relief=RAISED, width=28, anchor=W, bg="#3C395F", fg="white")
    lbl.grid(row=1, column=2)
    lbl = Label(headerframe, text="Options", relief=RAISED, width=28, anchor=W, bg="#3C395F", fg="white")
    lbl.grid(row=1, column=3)

    contentframe = ScrollableFrame(window)
    contentframe.pack(fill=BOTH)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()
            
            if (len(array) == 0):
                break

            lbl1 = Label(contentframe.scrollable_frame, text=(array[i][1]), width=28, anchor=W)
            lbl1.grid(column=0, row=(i+3))
            lbl2 = Label(contentframe.scrollable_frame, text=(array[i][2]), width=28, anchor=W)
            lbl2.grid(column=1, row=(i+3))
            lbl3 = Label(contentframe.scrollable_frame, text=(array[i][3]), width=28, anchor=W)
            lbl3.grid(column=2, row=(i+3))

            btnframe = Frame(contentframe.scrollable_frame)
            btnframe.grid(column=3, row=(i+3), padx=70)

            btn = Button(btnframe, text="C", command = partial(pyperclip.copy, array[i][3]), bg="blue", fg="white", border=0, width=2, pady=2) 
            btn.grid(column=0, row=0, pady=10, padx=5)

            btn1 = Button(btnframe, text="E", command = partial(editPopUp, array[i][0]), bg="yellow", fg="white", border=0, width=2, pady=2)
            btn1.grid(column=1, row=0, pady=10, padx=5)

            btn2 = Button(btnframe, text="D", command = partial(removeEntry, array[i][0]), bg="red", fg="white", border=0, width=2, pady=2)
            btn2.grid(column=2, row=0, pady=10, padx=5)

            i = i + 1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()