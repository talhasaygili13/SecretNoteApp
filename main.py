import base64
from tkinter import *
from tkinter import messagebox

window = Tk()
window.title('Secret Notes')
window.config(padx=30, pady=30)

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode(''.join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()

    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return ''.join(dec)
def save_and_encrypt():
    title = title_entry.get()
    message = input_text.get('1.0', END)
    secret_key = input_key.get()

    if len(title) == 0 or len(message) == 0 or len(secret_key) == 0:
        messagebox.showinfo(title='Error!', message='Please enter all info.')
    else:
        message_encrypted = encode(secret_key, message)
        try:
            with open('mysecret.txt', 'a') as file:
                file.write(f'\n{title} : \n{message_encrypted}')
        except FileNotFoundError:
            with open('mysecret.txt', 'w'):
                file.write(f'\n{title} : \n{message_encrypted}')
        finally:
            title_entry.delete(0, END)
            input_text.delete('1.0', END)
            input_key.delete(0, END)



def decrypt_note():
    message_encrypted = input_text.get('1.0', END)
    key = input_key.get()

    if len(message_encrypted) == 0 or len(key) == 0:
        messagebox.showinfo(title='Error!', message='Please enter all info.')
    else:
        try:
            decrypted_message = decode(key, message_encrypted)
            input_text.delete('1.0', END)
            input_text.insert('1.0', decrypted_message)
        except:
            messagebox.showinfo(title='Error!', message='Please enter encrypted text!')

FONT = ('Haveltica', 20, 'normal')


img = PhotoImage(file="secret_resize.png")
canvas = Canvas(height=100, width=100)
canvas.create_image(50, 50, image=img)
canvas.pack()

title_label = Label(text='Enter your title', font=FONT)
title_label.pack()

title_entry = Entry(width=40)
title_entry.pack()

text_label = Label(text='Enter your secret', font=FONT)
text_label.pack()

input_text = Text(width=50, height=25)
input_text.pack()


master_secret_label = Label(text='Enter master key', font=FONT)
master_secret_label.pack()

input_key = Entry(width=30)
input_key.pack()

save_button = Button(text='Save&Encrypt', command=save_and_encrypt)
save_button.pack()

decrypt_button = Button(text='Decrypt', command=decrypt_note)
decrypt_button.pack()
window.mainloop()