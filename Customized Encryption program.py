from tkinter import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tkinter import messagebox

class AESDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("Customized Encryption")
        self.root.geometry("600x600")
        self.root.config(bg="#5499c7")
        self.root.option_add("*Font", "Verdana" "11")

        # Create dropdown menu for selection
        self.mode_var = StringVar()
        self.mode_var.set("select")
        mode_label = Label(root, text="Operation:", bg="#5499c7")
        mode_label.pack(anchor="w", padx=10, pady=5)
        mode_menu = OptionMenu(root, self.mode_var, "Encrypt", "Decrypt")
        mode_menu.pack(anchor="w", padx=10)

        # Create input fields
        input_label = Label(root, text="Enter the data: - - - - - - - - - - - - - - - - - - - - - -", bg="#5499c7")
        input_label.pack(anchor="w", padx=10, pady=5)
        self.input_text = Entry(root)
        self.input_text.pack(anchor="s", padx=10)

        key_label = Label(root, text="Enter the Secret Key: - - - - - - - - - - - - - - - - - - - -", bg="#5499c7")
        key_label.pack(anchor="w", padx=10, pady=5)
        self.key_text = Entry(root)
        self.key_text.pack(anchor="s", padx=10, pady=5)

        # Create IV field
        self.iv_label = Label(root, text="Enter your IV: (Not applicable to ECB and CTR ) - - - - - - - -", bg="#5499c7" )
        self.iv_label.pack(anchor="w",padx=10, pady=5)
        self.iv_text = Entry(root)
        self.iv_text.pack(anchor='s',padx=10, pady=5)

        # Create checkboxes for key size and mode of operation
        self.key_size_var = IntVar()
        self.key_size_var.set(128)
        key_size_label = Label(root, text="Select the Key Size:", bg="#5499c7")
        key_size_label.pack(anchor="w", padx=10, pady=5)
        key_size_frame = Frame(root, bg="#5499c7")
        key_size_frame.pack(anchor="w", padx=10)
        Radiobutton(key_size_frame, text="128-bit", variable=self.key_size_var, value=128, bg="#5499c7").pack(side=LEFT)
        Radiobutton(key_size_frame, text="192-bit", variable=self.key_size_var, value=192, bg="#5499c7").pack(side=LEFT)
        Radiobutton(key_size_frame, text="256-bit", variable=self.key_size_var, value=256, bg="#5499c7").pack(side=LEFT)

        self.mode_of_operation_var = StringVar()
        self.mode_of_operation_var.set("ECB")
        mode_of_operation_label = Label(root, text="Mode of Operation:", bg="#5499c7")
        mode_of_operation_label.pack(anchor="w", padx=10, pady=5)
        mode_of_operation_frame = Frame(root, bg="#5499c7")
        mode_of_operation_frame.pack(anchor="w", padx=10)
        Radiobutton(mode_of_operation_frame, text="CBC", variable=self.mode_of_operation_var, value="CBC", bg="#5499c7").pack(side=LEFT)
        Radiobutton(mode_of_operation_frame, text="OFB", variable=self.mode_of_operation_var, value="OFB", bg="#5499c7").pack(side=LEFT)
        Radiobutton(mode_of_operation_frame, text="CTR", variable=self.mode_of_operation_var, value="CTR", bg="#5499c7").pack(side=LEFT)
        Radiobutton(mode_of_operation_frame, text="ECB", variable=self.mode_of_operation_var, value="ECB", bg="#5499c7").pack(side=LEFT)
        Radiobutton(mode_of_operation_frame, text="CFB", variable=self.mode_of_operation_var, value="CFB", bg="#5499c7").pack(side=LEFT)

        # Create process button
        process_button = Button(root, text="Generate ", command=self.process)
        process_button.pack(pady=10)

        # Create output area
        output_label = Label(root, text="Output:", bg="#5499c7")
        output_label.pack(anchor="w", padx=10, pady=5)
        self.output_text = Text(root, height=5, width=30)
        self.output_text.pack(anchor="w", padx=10)

    def process(self):
        mode = self.mode_var.get()
        input_text = self.input_text.get()
        key = self.key_text.get()
        key_size = self.key_size_var.get()
        mode_of_operation = self.mode_of_operation_var.get()
        iv = self.iv_text.get() if mode_of_operation in ["CBC", "OFB", "CFB"] else None

        # Validate IV length
        if iv and (len(iv) != 16):
            messagebox.showerror("Invalid IV", "IV should have a length of 16")
            return

        try:
            if mode == "Encrypt":
                if mode_of_operation == "ECB":
                    encrypted_text = self.encrypt_ecb(input_text, key, key_size)
                elif mode_of_operation == "CTR":
                    encrypted_text = self.encrypt_ctr(input_text, key, key_size)
                else:
                    encrypted_text = self.encrypt(input_text, key, key_size, mode_of_operation, iv)
                self.output_text.delete("1.0", END)
                self.output_text.insert(END, encrypted_text)
            elif mode == "Decrypt":
                if mode_of_operation == "ECB":
                    decrypted_text = self.decrypt_ecb(input_text, key, key_size)
                elif mode_of_operation == "CTR":
                    decrypted_text = self.decrypt_ctr(input_text, key, key_size)
                else:
                    decrypted_text = self.decrypt(input_text, key, key_size, mode_of_operation, iv)
                self.output_text.delete("1.0", END)
                self.output_text.insert(END, decrypted_text)
        except Exception as e:
            self.output_text.delete("1.0", END)
            self.output_text.insert(END, "Error: " + str(e))

    def encrypt(self, input_text, key, key_size, mode_of_operation, iv):
        key = self.pad_key(key, key_size)
        cipher = AES.new(key, self.get_mode_of_operation(mode_of_operation), IV=self.pad_iv(iv))
        encrypted_bytes = cipher.encrypt(pad(input_text.encode(), AES.block_size))
        return encrypted_bytes.hex()

    def decrypt(self, input_text, key, key_size, mode_of_operation, iv):
        key = self.pad_key(key, key_size)
        cipher = AES.new(key, self.get_mode_of_operation(mode_of_operation), IV=self.pad_iv(iv))
        decrypted_bytes = unpad(cipher.decrypt(bytes.fromhex(input_text)), AES.block_size)
        return decrypted_bytes.decode()

    def encrypt_ecb(self, input_text, key, key_size):
        key = self.pad_key(key, key_size)
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_bytes = cipher.encrypt(pad(input_text.encode(), AES.block_size))
        return encrypted_bytes.hex()

    def decrypt_ecb(self, input_text, key, key_size):
        key = self.pad_key(key, key_size)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_bytes = unpad(cipher.decrypt(bytes.fromhex(input_text)), AES.block_size)
        return decrypted_bytes.decode()
    
    def encrypt_ctr(self, input_text, key, key_size):
        key = self.pad_key(key, key_size)
        cipher = AES.new(key, AES.MODE_CTR, nonce=b'87654321')
        encrypted_bytes = cipher.encrypt(input_text.encode())
        return encrypted_bytes.hex()

    def decrypt_ctr(self, input_text, key, key_size):
        key = self.pad_key(key, key_size)
        cipher = AES.new(key, AES.MODE_CTR, nonce=b'87654321')
        decrypted_bytes = cipher.decrypt(bytes.fromhex(input_text))
        return decrypted_bytes.decode()

    def pad_key(self, key, key_size):
        if len(key) < key_size // 8:
            key = key.ljust(key_size // 8, '\0')
        elif len(key) > key_size // 8:
            key = key[:key_size // 8]
        return key.encode()

    def pad_iv(self, iv):
        if iv is not None:
            if len(iv) < AES.block_size:
                iv = iv.ljust(AES.block_size, '\0')
            elif len(iv) > AES.block_size:
                iv = iv[:AES.block_size]
            return iv.encode()
        else:
            return b'0123456789101112'

    def get_mode_of_operation(self, mode_of_operation):
        if mode_of_operation == "CBC":
            return AES.MODE_CBC
        elif mode_of_operation == "OFB":
            return AES.MODE_OFB
        elif mode_of_operation == "CFB":
            return AES.MODE_CFB

root = Tk()
AESDemo(root)
root.mainloop()
