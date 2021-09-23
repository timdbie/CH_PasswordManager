import sqlite3, hashlib, os
from tkinter import *
from tkinter import simpledialog
#from PIL import ImageTk, Image
from functools import partial

#base folder
base_folder = os.path.dirname(__file__)

#database code
with sqlite3.connect('pw.db') as db:
    cursor = db.cursor()

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
def popUp(text):
    answer = simpledialog.askstring("input string", text)
    print(answer)

    return answer

#Initiate window
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

    window.geometry('600x400')

    lbl = Label(window, text="Enter  Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="●")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
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

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    window.geometry('800x400')
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()
            
            if (len(array) == 0):
                break

            lbl1 = Label(window, text=(array[i][1]))
            lbl1.grid(column=0, row=(i+3))
            lbl2 = Label(window, text=(array[i][2]))
            lbl2.grid(column=1, row=(i+3))
            lbl3 = Label(window, text=(array[i][3]))
            lbl3.grid(column=2, row=(i+3))

            btn = Button(window, text="Delete", command=  partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=(i+3), pady=10)

            i = i +1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()