import tkinter as tk
from tkinter import ttk
import json
import socket
import threading




HOST = "127.0.0.1"
PORT = 1001
global usern
def createloginsignup(root):
    for widget in root.winfo_children():
        widget.destroy()
    root.title("Login/Signup")

    tk.Label(root,text="Login Or Signup",bg="#565C96",fg="#57F287",font=("Arial",20)).pack(pady=30)
    tk.Label(root,text="Username",bg="#565C96",fg="#57F287",font=("Arial",12)).pack(pady=3)
    txtUsername = tk.Entry(root, width=20,fg="#57F287",bg="#565C96", font=("Arial", 12), justify="center")
    txtUsername.pack(pady=10)
    tk.Label(root,text="Password",bg="#565C96",fg="#57F287",font=("Arial",12)).pack(pady=3)
    txtPassword = tk.Entry(root, width=20,fg="#57F287",bg="#565C96", font=("Arial", 12), justify="center")
    txtPassword.pack(pady=10)

    tk.Button(root, text="Login", width=12,bg="#565C96",fg="#57F287",command=lambda:sendlogin(txtUsername.get(),txtPassword.get())).pack(pady=20)
    tk.Button(root, text="Register", width=12,bg="#565C96",fg="#57F287",command= lambda:SendReg(txtUsername.get(),txtPassword.get())).pack(pady=20)

    tk.Label(text="PROGRAMMED BY AIDAN CHETTY",bg="#565C96",fg="#57F287",justify="center", font=("Arial",12)).pack(pady=200,padx=100)



def createmain(root):
    global chat_window, message_entry
    for widget in root.winfo_children():
        widget.destroy()
    root.title(f"Welcome {User}")
    style = ttk.Style()
    style.configure("TEntry", padding=6, relief="flat")
    style.configure("TButton", padding=6, relief="flat", background="#5865F2", foreground="white")

    frame_chat = tk.Frame(root, bg="#23272A")
    frame_chat.pack(padx=10, pady=10, fill="both", expand=True)

    scrollbar = ttk.Scrollbar(frame_chat)
    scrollbar.pack(side="right", fill="y")

    chat_window = tk.Text(frame_chat, wrap="word", bg="#23272A", fg="white",
                      font=("Segoe UI", 11), bd=0, padx=10, pady=10, yscrollcommand=scrollbar.set)
    chat_window.tag_configure("user", foreground="#57F287")
    chat_window.tag_configure("bot", foreground="#5865F2")
    chat_window.config(state="disabled")
    chat_window.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=chat_window.yview)

    input_frame = tk.Frame(root, bg="#2C2F33")
    input_frame.pack(fill="x", padx=10, pady=10)

    message_entry = ttk.Entry(input_frame, font=("Segoe UI", 11))
    message_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
    message_entry.bind("<Return>", lambda event: sendchatmsg(message_entry.get()))

    send_btn = ttk.Button(input_frame, text="Send", command= lambda: sendchatmsg(message_entry.get()))
    send_btn.pack(side="right")




def sendlogin(User,Pass):
    logpacket = {"Action":"Login","Username":User,"Password":Pass}
    sendmsg(logpacket)

def SendReg(User,Pass):
    regpacket = {"Action":"Register","Username":User,"Password":Pass}
    sendmsg(regpacket)

def bot_reply(user_msg):
    chat_window.config(state="normal")
    aipacket = {"Action":'AskAI',"Username":User,"Message":user_msg}
    sendmsg(aipacket)

def sendchatmsg(msg):
    inputAI = message_entry.get().strip()
    if inputAI:
        chat_window.config(state="normal")
        chat_window.insert(tk.END, f"You: {inputAI}\n", "user")
        chat_window.config(state="disabled")
        chat_window.see(tk.END)
        message_entry.delete(0, tk.END)
        root.after(500, lambda: bot_reply(inputAI))  # Simulate bot reply




def sendmsg(message):
    global sock
    if sock:
        sock.sendall(json.dumps(message).encode('utf-8'))

def listen_to_server():
    """Listen for server messages 24/7."""
    global sock
    global User
    buffer = ""

    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("Disconnected from server")
                break

            buffer += data.decode("utf-8")

            # Process all complete JSON objects (split by newline)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue

                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as e:
                    print("JSON decode error:", e, "Data:", line)
                    continue

                action = msg.get("Action")

                match action:
                    case "LoginSuccess":
                        print("Login Success")
                        User = msg.get("Username")
                        createmain(root)

                    case "RegisterSuccess":         
                        print("Register Success")
                        User = msg.get("Username")
                        createmain(root)

                    case "AiMessage":
                        response = msg.get("Message")
                        chat_window.insert(tk.END, response + "\n", "bot")
                        chat_window.config(state="disabled")
                        chat_window.see(tk.END)
        except Exception as e:
            print("Error receiving:", e)
            break


def connect():
    global sock
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((HOST,PORT))
    threading.Thread(target=listen_to_server, daemon=True).start()


def main():
    connect()
    global root
    root = tk.Tk()
    root.configure(bg="#565C96")
    root.geometry("500x800")
    root.resizable(False,False)
    createloginsignup(root)
    root.mainloop()


if __name__ == "__main__":
    main()