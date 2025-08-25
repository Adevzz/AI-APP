import socket
import threading
import json
import sqlite3
from openai import OpenAI

HOST = '127.0.0.1'
PORT = 1001
API_KEY = "sk-or-v1-"
BASE_URL = "https://openrouter.ai/api/v1"

client = OpenAI(base_url=BASE_URL,api_key=API_KEY)

DB_FILE = "Accounts.db"

# Initialize database and table if not exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tbl_user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT UNIQUE,
                Password TEXT
            )
        """)
        conn.commit()

# Handle login/register messages
def handle_message(message):
    action = message.get("Action") or message.get("action")

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        match action:
            case "Login" | "login":
                username = message.get("Username") or message.get("username")
                password = message.get("Password") or message.get("password")

                cursor.execute("SELECT Password FROM tbl_user WHERE Username = ?", (username,))
                result = cursor.fetchone()

                if result is None:
                    return {"Action": "LoginFail", "Reason": "Username Does Not Exist"}

                stored_password = result[0]
                if stored_password == password:
                    return {"Action": "LoginSuccess", "Username": username}
                else:
                    return {"Action": "LoginFail", "Reason": "Incorrect Password"}

            case "Register" | "register":
                username = message.get("Username") or message.get("username")
                password = message.get("Password") or message.get("password")

                # Check if username already exists
                cursor.execute("SELECT * FROM tbl_user WHERE Username = ?", (username,))
                result = cursor.fetchone()
                if result:
                    return {"Action": "RegisterFail", "Reason": "Account Exists"}

                # Insert new user
                cursor.execute("INSERT INTO tbl_user (Username, Password) VALUES (?, ?)", (username, password))
                conn.commit()
                return {"Action": "RegisterSuccess", "Username": username}
            
            case "AskAI":
                usernameforai = message.get("Username")
                messageforai = message.get("Message")

                completion = client.chat.completions.create(
                    model = 'deepseek/deepseek-r1-0528-qwen3-8b:free',
                    messages=[
                        {
                        
                        "role":"user",
                        "content": f"Hello My Username Is {usernameforai} my question is {messageforai}"
                        }
                        
                    ]
                )
                

                return {"Action": "AiMessage","Message" : completion.choices[0].message.content}

            case _:
                return {"Action": "Unknown", "Status": "Error"}

# Handle each client in a separate thread
def handle_client(conn, addr):
    print(f"Connection from {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print(f"Client {addr} disconnected")
                    break

                # Decode JSON from client
                try:
                    message = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    conn.sendall(json.dumps({"Action": "Error", "message": "Invalid JSON"}).encode('utf-8'))
                    continue

                # Handle message and send response
                response = handle_message(message)
                safe_json = json.dumps(response, ensure_ascii=False)
                conn.sendall((safe_json + "\n").encode("utf-8"))

            except ConnectionResetError:
                print(f"Client {addr} forcibly closed connection")
                break
            except Exception as e:
                print(f"Error with client {addr}: {e}")
                break

# Start the server
def start_server(host=HOST, port=PORT):
    init_db()  # Make sure the DB/table exist
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server is online at {host}:{port}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
