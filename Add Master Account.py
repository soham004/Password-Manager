import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import pickle
import getpass





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
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    message = info
    pad = "{"
    decipher = AES.new(hkey, AES.MODE_ECB)
    pt = decipher.decrypt(message).decode('utf-8')
    pad_index = pt.find(pad)
    result: str = pt[: pad_index]
    return result


def read_passwords():
    master_file = open(f"./data/Soham/soham_data.txt", "br")
    acc_dict = pickle.load(master_file)
    for key in acc_dict:  # Acc_dict is the dictionary of all the Domains added
        print(key+":")  # This makeArr contains an dict of all the accounts added in the domain and I am iterating it via variable key
        make_dict = acc_dict[key]  # Key contains the domain name
        for accs in make_dict:
            my_password = make_dict[accs]
            print(accs + "->" + decrypt(my_password))
    master_file.close()


def save_passwords():
    master_file = open(f"./data/Soham/soham_data.txt", "bw")
    passDict = {
        "Gmail": {"de.soham004@gmail.com": encrypt("soham@19082004"),
                  "christropher.avogadro@gmail.com": encrypt("latitude@e5400"),
                  "sohamde.kol@gmail.com": encrypt("latitude@e5400")},
        "Facebook": {"943345678": encrypt("latitude@e5400")}
    }
    pickle.dump(passDict, master_file, protocol=2)
    master_file.close()


def merge(dict1, dict2):
    res = {**dict1, **dict2}
    return res


# file = open(f"./data/soham/soham_data.txt", "br")
# acc_dict = pickle.load(file)
# another_dictionary = {"Microsoft": [{"de.soham@hotmail.com": encrypt("latitude@e5400")}]}
# final_dict = merge(acc_dict, another_dictionary)
# print(final_dict)
# file.close()

print("""
    Your password will not be shown on the terminal.
""")
username = input("Username: ")
account_password = getpass.getpass("Password: ")
confirm_password = getpass.getpass("Confirm Password: ")
if confirm_password == account_password:
    password = account_password
    os.mkdir(f"./data/{username}")
    k = open(f"./data/{username}/{username}.txt", "w")
    d = open(f"./data/{username}/{username.lower()}_data.txt", "bw")
    k.close()
    d.close()
    with open(f"./data/{username}/{username}.txt", "bw") as file:
        pickle.dump(encrypt(account_password), file)
        file.close()
    with open(f"./data/{username}/{username.lower()}_data.txt", "bw") as file_w:
        data_temp = {}
        pickle.dump(data_temp, file_w)
        file_w.close()
else:
    print("Passwords don't match")
