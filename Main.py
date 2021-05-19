import subprocess
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from tkinter import *
from tkinter import ttk
import os
import pickle
import pyperclip
import threading


dark_mode = True
password = ""


acc_id_x = 420
acc_id_y = 250

showing_password = False


def merge(dict1, dict2):
    res = {**dict1, **dict2}
    return res


def encrypt(info):
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    message = info
    block_size = 16
    pad = "{"
    padding = lambda s: s + (block_size - len(s) % block_size) * pad
    cipher = AES.new(hkey, AES.MODE_ECB)
    result = cipher.encrypt(padding(message).encode('utf-8'))
    return result


def decrypt(info):
    try:
        hash_obj = SHA256.new(password.encode('utf-8'))
        hkey = hash_obj.digest()
        message = info
        pad = "{"
        decipher = AES.new(hkey, AES.MODE_ECB)
        pt = decipher.decrypt(message).decode('utf-8')
        pad_index = pt.find(pad)
        result = pt[: pad_index]
    except UnicodeDecodeError:
        result = None
    except Exception:
        result = None
    return result


def master_login(event=None):
    global password
    master_acc_name = master_account_id.get()
    try:
        file_list = os.listdir(f"./data/{master_acc_name}")  # file list of the master account directory
    except Exception:
        file_list = []
    if f"{master_acc_name}.txt" in file_list:
        master_file = open(f"./data/{master_acc_name}/{master_acc_name}.txt", "br")
        master_password = pickle.load(master_file)
        master_file.close()
        master_account_id_error.config(text="")
        entered_pass = master_account_pass.get()
        password = entered_pass
        if entered_pass == decrypt(master_password):
            master_account_pass_error.config(text="")
            login_screen_place(1)
            show_hide_main_screen(0)

        else:
            master_account_pass_error.config(text="Password is incorrect!", foreground="red")
    else:
        master_account_id_error.config(text="Account does not exists!", foreground="red")


def login_screen_place(ids):
    if ids == 0:
        login_frame.pack(fill=BOTH, expand=True)
        master_account_pass.delete(0, "end")

    elif ids == 1:
        login_frame.pack_forget()


def show_hide_password():
    global showing_password
    if not showing_password:
        master_account_pass.config(show="")
        showing_password = True
    elif showing_password:
        master_account_pass.config(show="*")
        showing_password = False


def show_hide_main_screen(ind):
    if ind == 0:
        main_screen.pack(fill=BOTH, expand=True)

        list_box.delete(0, "end")

        id_ok = master_account_id.get().lower()
        master_file = open(f"./data/{id_ok}/{id_ok}_data.txt", "br")
        acc_dict = pickle.load(master_file)
        master_file.close()
        i = 0
        for keys in acc_dict:
            list_box.insert(i, keys)
            i += 1
        list_box.select_set(0)
    elif ind == 1:
        main_screen.pack_forget()


def show_hide_passwords_screen(index):
    global password
    if index == 0:
        password_list.delete(0, "end")
        key = list_box.get(ACTIVE)
        show_hide_main_screen(1)
        password_screen.pack(fill=BOTH, expand=True)
        id_ok = master_account_id.get().lower()
        master_file = open(f"./data/{id_ok}/{id_ok}_data.txt", "br")
        acc_dict = pickle.load(master_file)
        i = 0
        # This makeArr contains an ARRAY of all the accounts added in the domain and I am iterating it via variable key
        makeArr = acc_dict[key]  # Key contains the domain name
        for accs in makeArr:
            account_password = makeArr[accs]
            password_list.insert(i, (accs + "->" + decrypt(account_password)))
            i += 1
        password_list.select_set(0)
        master_file.close()
    elif index == 1:
        password_screen.pack_forget()
        show_hide_main_screen(0)


def copy_password():
    raw_password = password_list.get(ACTIVE)
    raw_password = str(raw_password).split("->")
    main_password = raw_password[1]
    pyperclip.copy(main_password)


def main_screen_done_function():
    show_hide_main_screen(1)
    login_screen_place(0)


def refresh():
    show_hide_main_screen(1)
    show_hide_main_screen(0)


def run_command(command):
    os.system(command)


if __name__ == '__main__':

    root = Tk()
    a = BooleanVar()
    h = BooleanVar()
    root.title("Password Manager")
    root.geometry("1200x750")
    # root.config(background='gray11')
    root.resizable(False, False)
    style = ttk.Style(root)
    root.tk.call('source', 'azure-dark.tcl')
    style.theme_use('azure-dark')

    # Login Page setup start
    login_frame = Frame(
        root
    )
    main_screen = ttk.Frame(
        root
    )
    password_screen = ttk.Frame(
        root
    )
    master_account_id_label = ttk.Label(
        login_frame,
        text="Master Account ID:",
        # fg="snow"
    )



    master_account_id = ttk.Entry(login_frame, foreground="gray11")
    master_account_id_error = ttk.Label(
        login_frame,
        text="",
        # fg="red",
        # bg='gray11'
    )

    master_account_pass_label = ttk.Label(
        login_frame,
        text="Master Account Password:",
        # fg="snow"
    )
    master_account_pass = ttk.Entry(
        login_frame,
        show="*",
        foreground="gray11"
    )
    master_account_pass.bind('<Return>', master_login)  # Binding enter key to login function
    master_account_id.bind('<Return>', master_login)  # Binding enter key to login function
    master_account_pass_error = ttk.Label(
        login_frame,
        text="",
        # fg="red",
        # bg='gray11'
    )
    login_button = ttk.Button(
        login_frame,
        text="Login",
        # fg="snow",
        # bg='gray11',
        command=lambda: master_login()
    )
    show_password_label = ttk.Label(
        login_frame,
        text="Show Password:",
        # fg="snow"
    )
    show_password_checkbutton = ttk.Checkbutton(
        login_frame,
        # bd=1,
        # bg='gray11',
        # active background='gray11',
        variable=a,
        command=lambda: show_hide_password()
    )
    login_screen_place(0)
    # Login Page setup end

    

    # Setup of main screen
    list_label = ttk.Label(
        main_screen,
        text="List of the added accounts:",
        # fg="snow"
    )
    list_box = Listbox(
        main_screen,
        bd=1,
        bg="gray14",
        fg="snow",
        width=80,
        height=25
    )
    main_screen_scrollbar = ttk.Scrollbar(
        main_screen
    )
    list_box.config(yscrollcommand=main_screen_scrollbar.set)
    main_screen_scrollbar.config(command=list_box.yview)
    add_accounts_button = ttk.Button(
        main_screen,
        text="Add Accounts",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=lambda: threading.Thread(target=run_command, args=(f"Acc_adder.py {master_account_id.get()} {master_account_pass.get()}",)).start()
    )
    del_accounts_button = ttk.Button(
        main_screen,
        text="Delete Accounts",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=lambda: threading.Thread(target=run_command, args=(f"Account_Deleter.py {master_account_id.get()} {master_account_pass.get()}",)).start()  # run_command(f"Account_Deleter.py {master_account_id.get()} {master_account_pass.get()}")
    )
    show_button = ttk.Button(
        main_screen,
        text="Show Accounts",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=lambda: show_hide_passwords_screen(0)
    )
    done_button = ttk.Button(
        main_screen,
        text="Done",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=main_screen_done_function
    )
    refresh_button = ttk.Button(
        main_screen,
        text="Refresh",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=lambda: refresh()
    )
    # done setup main screen

    # setup password screen
    password_list = Listbox(
        password_screen,
        bd=1,
        bg="gray14",
        fg="snow",
        width=80,
        height=25,
        selectbackground='blue2'
    )
    password_screen_scrollbar = ttk.Scrollbar(
        password_screen
    )
    password_list.config(yscrollcommand=password_screen_scrollbar.set)
    password_screen_scrollbar.config(command=password_list.yview)
    copy_button = ttk.Button(
        password_screen,
        text="Copy Password to Clipboard",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=copy_password
    )
    password_done_button = ttk.Button(
        password_screen,
        text="Done",
        # bg="gray11",
        # fg="snow",
        # font=("", 10),
        command=lambda: show_hide_passwords_screen(1)
    )

    master_account_id_label.place(x=acc_id_x, y=acc_id_y)

    master_account_id.place(x=acc_id_x,
                            y=(acc_id_y + 30),
                            width=350)

    master_account_id_error.place(x=(acc_id_x + 360), y=(acc_id_y + 20))

    master_account_pass_label.place(x=acc_id_x, y=(acc_id_y + 80))

    master_account_pass.place(x=acc_id_x,
                              y=(acc_id_y + 110),
                              width=350)
    master_account_pass_error.place(x=(acc_id_x + 360), y=(acc_id_y + 110))

    login_button.place(x=(acc_id_x + 225), y=(acc_id_y + 170))
    show_password_label.place(x=acc_id_x - 50, y=(acc_id_y + 170))
    show_password_checkbutton.place(x=acc_id_x + 90, y=(acc_id_y + 170))

    list_box.place(x=10, y=70)
    main_screen_scrollbar.place(x=815, y=70, width=20, height=655)
    list_label.place(x=10, y=20)
    show_button.place(x=900, y=200)
    add_accounts_button.place(x=900, y=250)
    refresh_button.place(x=900, y=300)
    del_accounts_button.place(x=900, y=350)
    done_button.place(x=900, y=400)

    password_done_button.place(x=900, y=250)
    password_list.place(x=10, y=70)
    password_screen_scrollbar.place(x=815, y=70, width=20, height=655)
    copy_button.place(x=900, y=200)



    root.mainloop()
