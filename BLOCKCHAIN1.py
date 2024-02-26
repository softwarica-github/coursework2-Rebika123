import tkinter as tk
from hashlib import sha256
from tkinter import simpledialog, messagebox
import secrets
import bcrypt

class Block:
    def __init__(self, number=0, previous_hash="0" * 64, data=None, nonce=0):
        self.number = number
        self.previous_hash = previous_hash
        self.data = data
        self.nonce = nonce

    def hash(self):
        hashing_text = str(self.number) + self.previous_hash + str(self.data) + str(self.nonce)
        h = sha256()
        h.update(hashing_text.encode('utf-8'))
        return h.hexdigest()

    def __str__(self):
        return f"Block#: {self.number}\nHash: {self.hash()}\nPrevious: {self.previous_hash}\nData: {self.data}\nNonce: {self.nonce}\n"

class Blockchain:
    difficulty = 4

    def __init__(self):
        self.chain = []

    def add(self, block):
        self.chain.append(block)

    def mine(self, block):
        if self.chain:
            block.previous_hash = self.chain[-1].hash()
        else:
            block.previous_hash = "0" * 64

        while block.hash()[:self.difficulty] != "0" * self.difficulty:
            block.nonce = secrets.randbits(32)

        self.add(block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            _previous = self.chain[i].previous_hash
            _current = self.chain[i - 1].hash()
            if _previous != _current or _current[:self.difficulty] != "0" * self.difficulty:
                return False
        return True

class User:
    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

class BlockchainApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Blockchain GUI")
        self.blockchain = Blockchain()
        self.current_user = None

        self.label = tk.Label(master, text="Blockchain Status")
        self.label.pack()

        self.textbox = tk.Text(master, height=10, width=50)
        self.textbox.pack()

        self.add_block_button = tk.Button(master, text="Add Block", command=self.add_block)
        self.add_block_button.pack()

        self.mine_block_button = tk.Button(master, text="Mine Block", command=self.mine_block)
        self.mine_block_button.pack()

        self.validate_button = tk.Button(master, text="Validate Blockchain", command=self.validate_blockchain)
        self.validate_button.pack()

        self.login_button = tk.Button(master, text="Login", command=self.login)
        self.login_button.pack()

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.pack()

    def update_textbox(self):
        self.textbox.delete(1.0, tk.END)
        for block in self.blockchain.chain:
            self.textbox.insert(tk.END, str(block) + "\n")

    def add_block(self):
        if not self.current_user:
            messagebox.showerror("Error", "You need to login first.")
            return

        data = simpledialog.askstring("Add Block", "Enter data for the new block:", parent=self.master)
        if data:
            self.blockchain.mine(Block(data=data))
            self.update_textbox()
            self.label.config(text="Block added successfully!")

    def mine_block(self):
        if not self.current_user:
            messagebox.showerror("Error", "You need to login first.")
            return

        data = simpledialog.askstring("Mine Block", "Enter data for the new block:", parent=self.master)
        if data:
            self.blockchain.mine(Block(data=data))
            self.update_textbox()
            self.label.config(text="Block mined successfully!")

    def validate_blockchain(self):
        if self.blockchain.is_valid():
            self.label.config(text="Blockchain is valid.")
        else:
            self.label.config(text="Blockchain is not valid.")

    def login(self):
        username = simpledialog.askstring("Login", "Enter your username:", parent=self.master)
        if not username:
            return

        password = simpledialog.askstring("Login", "Enter your password:", parent=self.master)
        if not password:
            return

        user = self.authenticate(username, password)
        if user:
            self.current_user = user
            messagebox.showinfo("Login", "Login successful.")
        else:
            messagebox.showerror("Login", "Invalid username or password.")

    def authenticate(self, username, password):
        # Check if the entered username and password match the default credentials
        if username == "username" and password == "password":
            # In a real application, you would validate the credentials against a database
            # Here, we're using a simple check
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return User(username, password_hash)
        return None

if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainApp(root)
    root.mainloop()
