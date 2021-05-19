from tkinter import Tk, ACTIVE, Listbox
from tkinter import ttk
import pickle
import sys
from tkinter import messagebox
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os


def decrypt(info):
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    message = info
    pad = "{"
    decipher = AES.new(hkey, AES.MODE_ECB)
    pt = decipher.decrypt(message).decode('utf-8')
    pad_index = pt.find(pad)
    result = pt[: pad_index]
    return result


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


password = ""

master_acc_name = sys.argv[1]
try:
    file_list = os.listdir(f"./data/{master_acc_name}")  # file list of the master account directory
except Exception:
    file_list = []
if f"{master_acc_name}.txt" in file_list:
    master_file = open(f"./data/{master_acc_name}/{master_acc_name}.txt", "br")
    master_password = pickle.load(master_file)
    master_file.close()
    entered_pass = sys.argv[2]
    password = entered_pass
    if entered_pass == decrypt(master_password):
        root = Tk()
        root.geometry("1200x750")
        root.resizable(False, False)
        # root.config(background='gray11')
        root.title("Delete Account(s)")
        style = ttk.Style(root)
        root.tk.call('source', 'azure-dark.tcl')
        style.theme_use('azure-dark')


        def show_hide_first_screen(opinion):  # the screen that appears at first with list of domains
            if opinion == 0:
                show_hide_second_screen(1)
                # show the screen
                list_of_domains.delete(0, "end")
                list_of_domains.place(x=10, y=70)
                first_screen_scrollbar.place(x=815, y=70, width=20, height=655)
                next_button.place(x=900, y=200)
                delete_domain_button.place(x=900, y=250)
                done_button.place(x=900, y=300)
                file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
                dictionary = pickle.load(file)
                file.close()
                i = 0
                for keys in dictionary:
                    list_of_domains.insert(i, keys)
                    i += 1
                list_of_domains.select_set(0)
            else:
                # hide the screen
                list_of_domains.place_forget()
                first_screen_scrollbar.place_forget()
                next_button.place_forget()
                delete_domain_button.place_forget()
                done_button.place_forget()


        def show_hide_second_screen(opinion):
            if opinion == 0:
                show_hide_first_screen(1)
                list_of_accounts.delete(0, "end")
                list_of_accounts.place(x=10, y=70)
                second_screen_scrollbar.place(x=815, y=70, width=20, height=655)
                delete_account_button.place(x=900, y=200)
                second_screen_done_button.place(x=900, y=250)
                # show the screen
                key = list_of_domains.get(ACTIVE)
                file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
                dictionary = pickle.load(file)
                file.close()
                account_list = dictionary[key]
                i = 0
                for account in account_list:
                    list_of_accounts.insert(i, account)
                    i += 1
                list_of_accounts.select_set(0)
            else:
                # hide the screen
                second_screen_scrollbar.place_forget()
                list_of_accounts.place_forget()
                delete_account_button.place_forget()
                second_screen_done_button.place_forget()


        def del_domain():
            domain_to_delete = list_of_domains.get(ACTIVE)
            file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
            dictionary = pickle.load(file)
            file.close()
            confirmation = messagebox.askquestion("Confirmation", "Do you want to delete the domain?", icon="warning")
            if confirmation == "yes":
                dictionary.pop(domain_to_delete)
                # print(dictionary)
                file_save = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "bw")
                pickle.dump(dictionary, file_save)
                file_save.close()
                show_hide_first_screen(1)
                show_hide_first_screen(0)
            else:
                messagebox.showinfo("Info", "Domain not deleted")


        def del_account():
            domain_name = list_of_domains.get(ACTIVE)
            account_name = list_of_accounts.get(ACTIVE)
            file_aww = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
            dictionary = pickle.load(file_aww)
            file_aww.close()
            account_list = dictionary[domain_name]
            confirmation = messagebox.askquestion("Are you sure?", "Do you want to delete the account?", icon="warning")
            if confirmation == "yes":
                account_list.pop(account_name)
                dictionary[domain_name] = account_list
                file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "bw")
                pickle.dump(dictionary, file)
                file.close()
                show_hide_second_screen(1)
                show_hide_second_screen(0)
            else:
                messagebox.showinfo("Info", "Account not deleted!")


        # first screen setup start
        list_of_domains = Listbox(
            root,
            bg="gray11",
            fg="snow",
            width=80,
            height=25
        )
        first_screen_scrollbar = ttk.Scrollbar(
            root
        )
        list_of_domains.config(yscrollcommand=first_screen_scrollbar.set)
        first_screen_scrollbar.config(command=list_of_domains.yview)
        next_button = ttk.Button(
            root,
            text="Next",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=lambda: show_hide_second_screen(0)
        )
        delete_domain_button = ttk.Button(
            root,
            text="Delete Domain",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=lambda: del_domain()
        )
        done_button = ttk.Button(
            root,
            text="Done",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=lambda: sys.exit()
        )
        # first screen setup end

        # second screen setup start
        list_of_accounts = Listbox(
            root,
            bg="gray11",
            fg="snow",
            width=80,
            height=25
        )
        second_screen_scrollbar = ttk.Scrollbar(
            root
        )
        list_of_accounts.config(yscrollcommand=second_screen_scrollbar.set)
        second_screen_scrollbar.config(command=list_of_accounts.yview)
        delete_account_button = ttk.Button(
            root,
            text="Delete Account",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=lambda: del_account()
        )
        second_screen_done_button = ttk.Button(
            root,
            text="Done",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=lambda: show_hide_first_screen(0)
        )
        # second screen setup end
        # file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
        # dictionary = pickle.load(file)
        # file.close()
        # i = 0
        # for keys in dictionary:
        #     list_of_domains.insert(i, keys)
        #     i += 1
        show_hide_first_screen(0)
        root.mainloop()
