# Password-Manager
A simple but messy application of Tkinter and pycryptodome to make a password manager in python


### Usage-
1. First make a master account for the password manager by running the "Add Master Account.py" script
2. Nothing more just run the "Main.py" , login with the master account name and password and Never Forget Your Passwords Again!
3. You can add accounts by pressing the "Add Accounts" button.
4. The Domain is the name of the website on which you made the account(Like - Google, Github, Amazon, Microsoft, Microsoft Teams etc.)
5. To generate a strong password press the "Generate Password" button beside the password input field.

### Prerequisites-
You need to install the following packages to use the program-
1. Pycryptodome
2. Pyperclip

Run the following command in the shell to install the required packages:-
```sh
pip install --upgrade pycryptodome pyperclip tkinter
```

### Pros-
1. This is a open-source project so there is no hidden malware or data collecting sript.
2. This works offline and you don't need a internet connection to work with it.
3. It can also generate a strong password for you.
4. This password manager encrypts the passwords with a strong 256-bit encryption so your passwords are totally safe.
5. The passwords can only be decrypted by your master password.
6. It copies your password to your clipboard with a single button.
7. Finally, you can have more than one master accounts(which you can create by running the "Add Master Account.py" script). This means you can use the same password manager for your whole family.

### Cons-
1. This DOES NOT makes any backup of your passwords so you have to make backups yourself(just copy the "data" folder to a safe place).
2. I have a very less experience in coding as I am only 16 years old, so I don't think this is the best way to do it(this will definately get better with time).
3. There are some known issues

## Known Issues-
1. It doesn't shows generate password while adding accounts to existing domain.(I will add it later)
