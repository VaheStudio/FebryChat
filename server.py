import socket
import threading
import json
import time
import sqlite3
from datetime import datetime
import hashlib
import os

class FebryChatServer:
    def __init__(self, host='192.168.1.102', port=7981):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {username: {'socket': socket, 'address': address}}
        self.running = False
        self.setup_database()
        
    def setup_database(self):
        self.db_conn = sqlite3.connect('febrychat.db', check_same_thread=False)
        self.db_cursor = self.db_conn.cursor()
        
        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                nickname TEXT,
                avatar TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS friends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1 TEXT NOT NULL,
                user2 TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user1, user2)
            )
        ''')
        
        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message_type TEXT DEFAULT 'text',
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        

        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.db_conn.commit()
        self.register_user('admin', 'admin123', '系统管理员')
        
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username, password, nickname=None):
        try:
            hashed_password = self.hash_password(password)
            nickname = nickname or username
            self.db_cursor.execute(
                "INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)",
                (username, hashed_password, nickname)
            )
            self.db_conn.commit()
            return True, "注册成功"
        except sqlite3.IntegrityError:
            return False, "用户名已存在"
        except Exception as e:
            return False, f"注册失败: {str(e)}"
    
    def authenticate_user(self, username, password):
        hashed_password = self.hash_password(password)
        self.db_cursor.execute(
            "SELECT username, nickname FROM users WHERE username=? AND password=?",
            (username, hashed_password)
        )
        result = self.db_cursor.fetchone()
        return result is not None, result
    
    def add_friend(self, user1, user2):
        try:

            self.db_cursor.execute(
                "SELECT id FROM friends WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)",
                (user1, user2, user2, user1)
            )
            if self.db_cursor.fetchone():
                return False, "已经是好友"
            

            self.db_cursor.execute(
                "INSERT INTO friends (user1, user2) VALUES (?, ?)",
                (user1, user2)
            )
            self.db_conn.commit()
            return True, "添加好友成功"
        except Exception as e:
            return False, f"添加好友失败: {str(e)}"
    
    def send_friend_request(self, from_user, to_user):

        try:

            self.db_cursor.execute(
                "SELECT id FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'",
                (from_user, to_user)
            )
            if self.db_cursor.fetchone():
                return False, "已发送好友请求，等待对方确认"
            
            self.db_cursor.execute(
                "INSERT INTO friend_requests (from_user, to_user) VALUES (?, ?)",
                (from_user, to_user)
            )
            self.db_conn.commit()
            return True, "好友请求发送成功"
        except Exception as e:
            return False, f"发送好友请求失败: {str(e)}"
    
    def get_friend_requests(self, username):

        self.db_cursor.execute(
            "SELECT from_user, created_at FROM friend_requests WHERE to_user=? AND status='pending'",
            (username,)
        )
        return self.db_cursor.fetchall()
    
    def handle_friend_request(self, from_user, to_user, action):
        try:
            if action == 'accept':
                success, message = self.add_friend(from_user, to_user)
                if success:
                    self.db_cursor.execute(
                        "UPDATE friend_requests SET status='accepted' WHERE from_user=? AND to_user=?",
                        (from_user, to_user)
                    )
                    self.db_conn.commit()
                    return True, "已接受好友请求"
                else:
                    return False, message
            else:
                self.db_cursor.execute(
                    "UPDATE friend_requests SET status='rejected' WHERE from_user=? AND to_user=?",
                    (from_user, to_user)
                )
                self.db_conn.commit()
                return True, "已拒绝好友请求"
        except Exception as e:
            return False, f"处理好友请求失败: {str(e)}"
    
    def get_friends(self, username):
        self.db_cursor.execute(
            "SELECT user1, user2 FROM friends WHERE user1=? OR user2=?",
            (username, username)
        )
        friends = []
        for row in self.db_cursor.fetchall():
            friend = row[0] if row[0] != username else row[1]
            friends.append(friend)
        return friends
    
    def save_message(self, sender, receiver, content, message_type='text'):

        self.db_cursor.execute(
            "INSERT INTO messages (sender, receiver, content, message_type) VALUES (?, ?, ?, ?)",
            (sender, receiver, content, message_type)
        )
        self.db_conn.commit()
        return self.db_cursor.lastrowid
    
    def get_chat_history(self, user1, user2, limit=50):

        self.db_cursor.execute(
            """SELECT sender, receiver, content, message_type, timestamp 
               FROM messages 
               WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
               ORDER BY timestamp DESC LIMIT ?""",
            (user1, user2, user2, user1, limit)
        )
        return self.db_cursor.fetchall()
    
    def broadcast_online_status(self, username, online=True):

        status = "online" if online else "offline"
        message = {
            'type': 'status_update',
            'username': username,
            'status': status
        }
        

        friends = self.get_friends(username)
        for friend in friends:
            if friend in self.clients:
                self.send_message_to_client(friend, message)
    
    def send_message_to_client(self, username, message):

        if username in self.clients:
            try:
                client_socket = self.clients[username]['socket']
                client_socket.send(json.dumps(message).encode('utf-8'))
            except:

                if username in self.clients:
                    del self.clients[username]
    
    def handle_client(self, client_socket, address):
        print(f"新连接: {address}")
        
        current_user = None
        
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    response = self.process_message(message, client_socket)
                    
                    if response:
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        
                except json.JSONDecodeError:
                    error_response = {'type': 'error', 'message': '无效的JSON格式'}
                    client_socket.send(json.dumps(error_response).encode('utf-8'))
                    
        except Exception as e:
            print(f"客户端处理错误: {e}")
        finally:
            if current_user:
                if current_user in self.clients:
                    del self.clients[current_user]
                self.broadcast_online_status(current_user, False)
                print(f"用户 {current_user} 已断开连接")
            client_socket.close()
    
    def process_message(self, message, client_socket):
        msg_type = message.get('type')
        
        if msg_type == 'login':
            return self.handle_login(message, client_socket)
        elif msg_type == 'register':
            return self.handle_register(message)
        elif msg_type == 'send_message':
            return self.handle_send_message(message)
        elif msg_type == 'get_friends':
            return self.handle_get_friends(message)
        elif msg_type == 'add_friend':
            return self.handle_add_friend(message)
        elif msg_type == 'get_friend_requests':
            return self.handle_get_friend_requests(message)
        elif msg_type == 'handle_friend_request':
            return self.handle_friend_request_response(message)
        elif msg_type == 'get_chat_history':
            return self.handle_get_chat_history(message)
        else:
            return {'type': 'error', 'message': '未知的消息类型'}
    
    def handle_login(self, message, client_socket):
        username = message.get('username')
        password = message.get('password')
        
        success, user_info = self.authenticate_user(username, password)
        
        if success:
            self.clients[username] = {'socket': client_socket, 'address': client_socket.getpeername()}
            self.broadcast_online_status(username, True)
            

            friend_requests = self.get_friend_requests(username)
            
            return {
                'type': 'login_response',
                'success': True,
                'username': username,
                'nickname': user_info[1],
                'friend_requests': friend_requests,
                'message': '登录成功'
            }
        else:
            return {
                'type': 'login_response',
                'success': False,
                'message': '用户名或密码错误'
            }
    
    def handle_register(self, message):
        username = message.get('username')
        password = message.get('password')
        nickname = message.get('nickname', username)
        
        success, msg = self.register_user(username, password, nickname)
        return {
            'type': 'register_response',
            'success': success,
            'message': msg
        }
    
    def handle_send_message(self, message):
        sender = message.get('sender')
        receiver = message.get('receiver')
        content = message.get('content')
        msg_type = message.get('message_type', 'text')
        
        message_id = self.save_message(sender, receiver, content, msg_type)
        

        if receiver in self.clients:
            realtime_message = {
                'type': 'new_message',
                'sender': sender,
                'receiver': receiver,
                'content': content,
                'message_type': msg_type,
                'timestamp': datetime.now().isoformat(),
                'message_id': message_id
            }
            self.send_message_to_client(receiver, realtime_message)
        
        return {
            'type': 'send_message_response',
            'success': True,
            'message_id': message_id,
            'timestamp': datetime.now().isoformat()
        }
    
    def handle_get_friends(self, message):

        username = message.get('username')
        friends = self.get_friends(username)
        

        friends_with_status = []
        for friend in friends:
            online = friend in self.clients
            friends_with_status.append({
                'username': friend,
                'online': online
            })
        
        return {
            'type': 'friends_list',
            'friends': friends_with_status
        }
    
    def handle_add_friend(self, message):
        from_user = message.get('from_user')
        to_user = message.get('to_user')
        
        self.db_cursor.execute("SELECT username FROM users WHERE username=?", (to_user,))
        if not self.db_cursor.fetchone():
            return {
                'type': 'add_friend_response',
                'success': False,
                'message': '用户不存在'
            }
        
        success, msg = self.send_friend_request(from_user, to_user)
    
        if success and to_user in self.clients:
            notification = {
                'type': 'new_friend_request',
                'from_user': from_user
            }
            self.send_message_to_client(to_user, notification)
        
        return {
            'type': 'add_friend_response',
            'success': success,
            'message': msg
        }
    
    def handle_get_friend_requests(self, message):
        username = message.get('username')
        requests = self.get_friend_requests(username)
        
        return {
            'type': 'friend_requests_list',
            'requests': requests
        }
    
    def handle_friend_request_response(self, message):
        from_user = message.get('from_user')
        to_user = message.get('to_user')
        action = message.get('action')  # 'accept' or 'reject'
        
        success, msg = self.handle_friend_request(from_user, to_user, action)
        if success and action == 'accept' and from_user in self.clients:
            notification = {
                'type': 'friend_request_accepted',
                'by_user': to_user
            }
            self.send_message_to_client(from_user, notification)
        
        return {
            'type': 'friend_request_response',
            'success': success,
            'message': msg
        }
    
    def handle_get_chat_history(self, message):
        user1 = message.get('user1')
        user2 = message.get('user2')
        limit = message.get('limit', 50)
        
        history = self.get_chat_history(user1, user2, limit)
        
        return {
            'type': 'chat_history',
            'history': history
        }
    
    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"FebryChat 服务器已启动在 {self.host}:{self.port}")
            print("等待客户端连接...")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except KeyboardInterrupt:
                    print("\n服务器正在关闭...")
                    break
                except Exception as e:
                    print(f"接受连接时出错: {e}")
                    
        except Exception as e:
            print(f"启动服务器失败: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.db_conn.close()
            print("服务器已关闭")

if __name__ == "__main__":
    server = FebryChatServer()
    server.start_server()

## 制作不易，Star一下不过分吧？