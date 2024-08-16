from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import pickle
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import sys
import os
import StrongPasswordGen

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

fg = 'snow'

showing_password = False
new_showing_password = False


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

        def show_hide_add_existing_screen(ids):
            if ids == 0:
                show_hide_existing_screen(1)

                add_account_id.place(x=acc_id_x, y=(acc_id_y - 20), width=300)
                add_account_id_label.place(x=acc_id_x, y=(acc_id_y - 50))
                add_account_id_error.place(x=(acc_id_x + 270), y=(acc_id_y + 20))

                add_account_pass.place(x=acc_id_x, y=(acc_id_y + 70), width=300)
                add_account_pass_error.place(x=(acc_id_x + 270), y=(acc_id_y + 70))
                add_account_pass_label.place(x=acc_id_x, y=(acc_id_y + 45))
                add_account_pass_gen_button.place(x=(acc_id_x + 310), y=(acc_id_y + 70))

                add_add_button.place(x=(acc_id_x + 210), y=(acc_id_y + 120))
                add_cancel_button.place(x=(acc_id_x + 210), y=(acc_id_y + 170))
                add_show_password_label.place(x=acc_id_x - 20, y=(acc_id_y + 120))
                add_show_password_checkbutton.place(x=acc_id_x + 115, y=(acc_id_y + 120))

            elif ids == 1:
                add_account_pass.delete(0, "end")
                add_account_id.place_forget()
                add_account_id_label.place_forget()
                add_account_id_error.place_forget()

                add_account_pass.place_forget()
                add_account_pass_error.place_forget()
                add_account_pass_label.place_forget()
                add_account_pass_gen_button.place_forget()

                add_add_button.place_forget()
                add_cancel_button.place_forget()
                add_show_password_label.place_forget()
                add_show_password_checkbutton.place_forget()


        def add_to_existing_domain():
            domain_name = list_of_domains.get(ACTIVE)
            file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
            acc_dict = pickle.load(file)
            temp_dict = acc_dict[domain_name]
            password_dict = {add_account_id.get(): encrypt(add_account_pass.get())}
            permanent_dict = merge(temp_dict, password_dict)
            acc_dict[domain_name] = permanent_dict
            file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "bw")
            pickle.dump(acc_dict, file, protocol=2)
            file.close()
            messagebox.showinfo("Info", "Account Added Successfully")
            show_hide_add_existing_screen(1)
            show_hide_existing_screen(0)


        def add_new_domain():
            domain_name = add_new_domain_entry.get()
            account_name = add_new_account_id.get()
            account_password = add_new_account_pass.get()
            if domain_name != "" and account_name != "" and account_password != "":
                account_password = encrypt(account_password)
                with open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br") as file:
                    temp_dict = pickle.load(file)
                if domain_name not in temp_dict:
                    adding_dict = {domain_name: {account_name: account_password}}
                    per_dict = merge(temp_dict, adding_dict)
                    with open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "bw") as file:
                        pickle.dump(per_dict, file)
                    messagebox.showinfo("Info", "Domain Added Successfully.")
                else:
                    confirmation = messagebox.askquestion("Confirmation", "Domain already exists do you want to overwrite it?\n(All your previous passwords will be lost)", icon="warning")
                    if confirmation == "yes":
                        adding_dict = {domain_name: {account_name: account_password}}
                        per_dict = merge(temp_dict, adding_dict)
                        with open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "bw") as file:
                            pickle.dump(per_dict, file)
                        messagebox.showinfo("Info", "Domain Added Successfully.")
                    else:
                        messagebox.showinfo("Info", "Domain Addition Cancelled.")
                show_hide_add_new_screen(1)
                show_hide_intro_screen(0)
            elif domain_name == "":
                messagebox.showerror("Information Invalid", "Please enter a domain name.")
            elif account_name == "":
                messagebox.showerror("Information Invalid", "Please enter a account name.")
            elif account_password == "":
                messagebox.showerror("Information Invalid", "Please enter the password.")



        def show_hide_intro_screen(ind):
            if ind == 0:
                ooo_done_button.place(x=200, y=300)
                existing_intro_domain.place(x=200, y=250)
                new_intro_domain_button.place(x=600, y=250)
            else:
                ooo_done_button.place_forget()
                existing_intro_domain.place_forget()
                new_intro_domain_button.place_forget()


        def show_hide_existing_screen(ind):
            if ind == 0:
                list_of_domains.delete(0, "end")
                scrollbar.place(x=815, y=70, width=20, height=655)
                show_hide_intro_screen(1)
                existing_domain_next_button.place(x=900, y=200)
                existing_domain_done_button.place(x=900, y=250)
                list_of_domains.place(x=10, y=70)
                i = 0
                file = open(f"./data/{master_acc_name}/{master_acc_name.lower()}_data.txt", "br")
                directory = pickle.load(file)
                file.close()
                for keys in directory:
                    list_of_domains.insert(i, keys)
                    i += 1
                list_of_domains.select_set(0)
            else:
                list_of_domains.place_forget()
                scrollbar.place_forget()
                existing_domain_next_button.place_forget()
                existing_domain_done_button.place_forget()


        def add_show_hide_password():
            global showing_password
            if not showing_password:
                add_account_pass.config(show="")
                showing_password = True
            elif showing_password:
                add_account_pass.config(show="*")
                showing_password = False


        def add_new_show_hide_password():
            global new_showing_password
            if not new_showing_password:
                add_new_account_pass.config(show="")
                new_showing_password = True
            elif new_showing_password:
                add_new_account_pass.config(show="*")
                new_showing_password = False


        def show_hide_add_new_screen(ids):
            if ids == 0:
                show_hide_existing_screen(1)
                show_hide_intro_screen(1)
                add_new_domain_label.place(x=acc_id_x, y=(acc_id_y - 50))
                add_new_domain_entry.place(x=acc_id_x, y=(acc_id_y - 20), width=300)
                add_new_account_id_label.place(x=acc_id_x, y=acc_id_y + 30)
                add_new_account_id.place(x=acc_id_x, y=(acc_id_y + 55), width=300)
                add_new_account_id_error.place(x=(acc_id_x + 270), y=(acc_id_y + 50))
                add_new_account_pass.place(x=acc_id_x, y=(acc_id_y + 130), width=300)
                add_new_account_pass_error.place(x=(acc_id_x + 270), y=(acc_id_y + 90))
                add_new_account_pass_label.place(x=acc_id_x, y=(acc_id_y + 105))
                add_new_account_pass_gen_button.place(x=(acc_id_x + 310), y=(acc_id_y + 130))

                add_new_add_button.place(x=(acc_id_x + 210), y=(acc_id_y + 190))
                add_new_cancel_button.place(x=(acc_id_x + 210), y=(acc_id_y + 240))
                add_new_show_password_label.place(x=acc_id_x - 20, y=(acc_id_y + 180))
                add_new_show_password_checkbutton.place(x=acc_id_x + 115, y=(acc_id_y + 180))

            elif ids == 1:
                add_new_domain_entry.delete(0, "end")
                add_new_account_pass.delete(0, "end")
                add_new_account_id.delete(0, "end")

                add_new_domain_label.place_forget()
                add_new_domain_entry.place_forget()

                add_new_account_id.place_forget()
                add_new_account_id_label.place_forget()
                add_new_account_id_error.place_forget()

                add_new_account_pass.place_forget()
                add_new_account_pass_error.place_forget()
                add_new_account_pass_label.place_forget()
                add_new_account_pass_gen_button.place_forget()

                add_new_add_button.place_forget()
                add_new_cancel_button.place_forget()
                add_new_show_password_label.place_forget()
                add_new_show_password_checkbutton.place_forget()


        def add_new_cancel():
            show_hide_add_new_screen(1)
            show_hide_intro_screen(0)


        def add_cancel():
            show_hide_add_existing_screen(1)
            show_hide_existing_screen(0)


        def existing_done():
            show_hide_existing_screen(1)
            show_hide_intro_screen(0)


        def fucking_ass_hole():
            new_intro_domain_button.place_forget()
            ooo_done_button.place_forget()
            existing_intro_domain.place_forget()
            sys.exit()


        def add_new_pass_gen():
            global new_showing_password
            add_new_account_pass.delete(0, "end")
            strong_pass = StrongPasswordGen.gen_pass()
            add_new_account_pass.insert(END, strong_pass)
            add_new_account_pass.config(show="")
            new_showing_password = True
            add_new_show_password_checkbutton.config(variable=b)


        def add_pass_gen():
            global showing_password
            add_account_pass.delete(0, "end")
            strong_pass = StrongPasswordGen.gen_pass()
            add_account_pass.insert(END, strong_pass)
            add_account_pass.config(show="")
            showing_password = True
            add_show_password_checkbutton.config(variable=b)




        root = Tk()
        root.geometry("1200x750")
        # root.config(background='gray11')
        root.title("Password Adder")
        # root.config(background='gray11')
        root.resizable(False, False)
        style = ttk.Style(root)
        root.tk.call('source', 'azure.tcl')
        root.tk.call("set_theme", "dark")
        root.iconbitmap("icon.ico")
        acc_id_x = 420
        acc_id_y = 250
        a = BooleanVar()
        b = BooleanVar(value=True)

        def merge(dict1, dict2):
            res = {**dict1, **dict2}
            return res


        existing_intro_domain = ttk.Button(
            root,
            text="Add Password To Existing Domain",
            # bg="gray11",
            # fg="snow",
            command=lambda: show_hide_existing_screen(0)
        )
        new_intro_domain_button = ttk.Button(
            root,
            text="Add A New Domain",
            # bg="gray11",
            # fg="snow",
            command=lambda: show_hide_add_new_screen(0)
        )
        ooo_done_button = ttk.Button(
            root,
            text="Done Adding",
            # bg="gray11",
            # fg="snow",
            command=fucking_ass_hole
        )
        # Intro screen setup end
        add_account_id_label = ttk.Label(
            root,
            text="Account Username :",
            # fg="snow",
            # bg='gray11'
        )
        add_account_id = ttk.Entry(
            root,
            foreground=fg
        )
        add_account_id_error = ttk.Label(
            root,
            text="",
            # fg="red",
            # bg='gray11'
        )
        add_account_pass_label = ttk.Label(
            root,
            text="Username Password:",
            # fg="snow",
            # bg='gray11'
        )
        add_account_pass_gen_button = ttk.Button(
            root,
            text="Generate Password",
            command=add_pass_gen
        )
        add_account_pass = ttk.Entry(
            root,
            show="*",
            foreground=fg
        )
        add_account_pass_error = ttk.Label(
            root,
            text="",
            # fg="red",
            # bg='gray11'
        )
        add_add_button = ttk.Button(
            root,
            text="Add",
            # fg="snow",
            # bg='gray11',
            command=lambda: add_to_existing_domain()
        )
        add_cancel_button = ttk.Button(
            root,
            text="Cancel",
            # fg="snow",
            # bg='gray11',
            command=add_cancel
        )
        add_show_password_label = ttk.Label(
            root,
            text="Show Password:",
            # fg="snow",
            # bg='gray11'
        )

        add_show_password_checkbutton = ttk.Checkbutton(
            root,
            # bd=1,
            # bg='gray11',
            # activebackground='gray11',
            command=lambda: add_show_hide_password(),
            variable=a
        )

        add_new_domain_label = ttk.Label(
            root,
            text="Domain Name : ",
            # fg="snow",
            # bg='gray11'
        )
        add_new_domain_entry = ttk.Entry(
            root,
            foreground=fg
        )
        add_new_account_pass_gen_button = ttk.Button(
            root,
            text="Generate Password",
            command=add_new_pass_gen
        )
        add_new_account_id_label = ttk.Label(
            root,
            text="Account Username :",
            # fg="snow",
            # bg='gray11'
        )
        add_new_account_id = ttk.Entry(
            root,
            foreground=fg
        )
        add_new_account_id_error = ttk.Label(
            root,
            text="",
            foreground="red",
            # bg='gray11'
        )
        add_new_account_pass_label = ttk.Label(
            root,
            text="Username Password:",
            # fg="snow",
            # bg='gray11'
        )
        add_new_account_pass = ttk.Entry(
            root,
            show="*",
            foreground=fg
        )
        add_new_account_pass_error = ttk.Label(
            root,
            text="",
            # fg="red",
            # bg='gray11'
        )
        add_new_add_button = ttk.Button(
            root,
            text="Add",
            # fg="snow",
            # bg='gray11',
            command=lambda: add_new_domain()
        )
        add_new_cancel_button = ttk.Button(
            root,
            text="Cancel",
            # fg="snow",
            # bg='gray11',
            command=add_new_cancel
        )
        add_new_show_password_label = ttk.Label(
            root,
            text="Show Password:",
            # fg="snow",
            # bg='gray11'
        )
        add_new_show_password_checkbutton = ttk.Checkbutton(
            root,
            # bd=1,
            # bg='gray11',
            # activebackground='gray11',
            command=lambda: add_new_show_hide_password(),
            variable=a
        )

        list_of_domains = Listbox(
            root,
            # bd=1,
            # bg="gray14",
            # fg="snow",
            width=80,
            height=25
        )
        scrollbar = ttk.Scrollbar(
            root
        )
        list_of_domains.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=list_of_domains.yview)
        existing_domain_next_button = ttk.Button(
            root,
            text="Next",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=lambda: show_hide_add_existing_screen(0)
        )
        existing_domain_done_button = ttk.Button(
            root,
            text="Done",
            # bg="gray11",
            # fg="snow",
            # bd=1,
            command=existing_done
        )
        show_hide_intro_screen(0)
        root.mainloop()
        root.quit()
