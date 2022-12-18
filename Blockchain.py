import json
import hashlib
import time
import datetime
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode

backend = default_backend()

class Blockchain(object):
    def __init__(self):
        self.data_dir = 'data'
        self.messages=self.data_dir+"/messages"
        self.users=self.data_dir+"/users"
        self.connections=self.data_dir+"/connections"
        self.salt_file=self.data_dir+"/salt.block"
        self.public_data=self.data_dir+"/public_data.block"

        self.salt = os.urandom(128)
        if not(os.path.exists(self.data_dir)):
            os.mkdir(self.data_dir)
        if not(os.path.exists(self.messages)):
            os.mkdir(self.messages)
        if not(os.path.exists(self.users)):
            os.mkdir(self.users)
        if not(os.path.exists(self.connections)):
            os.mkdir(self.connections)
        if not(os.path.exists(self.public_data)):
            f=open(self.public_data, 'w')
            f.close()
        if not(os.path.exists(self.salt_file)):
            f=open(self.salt_file, 'w')
            f.write(b64encode(self.salt).decode('utf-8'))
        else:
            f = open(self.salt_file)
            self.salt = f.read()
            f.close()
            self.salt = b64decode(self.salt)


    def create_user(self, login, password, data=""):
        log_hash=hashlib.sha256(login.encode('utf-8')).hexdigest()
        pw_hash=hashlib.sha256(password.encode('utf-8')).hexdigest()
        if (os.path.exists(self.users+"/"+log_hash+".block")):
            return None


        f=open(self.users+"/"+log_hash+".block", 'w')
        user = {
            "login": "",
            "name": "",
            "surname": "",
            "pw_hash": "",
            "data": "",
            "token": ""
        }
        user["login"]=login
        user["pw_hash"]=pw_hash
        user["token"]=hashlib.sha256((password+pw_hash).encode('utf-8')).hexdigest()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(bytes(str(hashlib.sha256((password + pw_hash).encode('utf-8')).hexdigest()), encoding='utf-8')))
        fern = Fernet(key)
        f.write(fern.encrypt(bytes(json.dumps(user), encoding='utf-8')).decode('utf-8'))
        f.close()
        os.mkdir(self.messages+"/"+log_hash)
        f=open(self.connections+"/"+log_hash+".block", 'w')
        conn={
            "users":[]
        }
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        keyv = hashlib.sha256(log_hash.encode('utf-8')).hexdigest()
        key = base64.urlsafe_b64encode(kdf.derive(bytes(keyv, encoding='utf-8')))
        fern = Fernet(key)
        f.write(fern.encrypt(bytes(json.dumps(conn), encoding='utf-8')).decode('utf-8'))

        f.close()
        
        f=open(self.public_data, 'r')
        users=f.read().split("; ")
        users.append(login)
        f.close()
        f=open(self.public_data, 'w')
        f.write(users[0])
        for i in range(1, len(users)):
            f.write("; "+users[i])
        f.close()
        
        return hashlib.sha256((password+pw_hash).encode('utf-8')).hexdigest()

    def send_message(self, login_from, login_to, message1, token):# will work only with right token
        from_hash=hashlib.sha256(login_from.encode('utf-8')).hexdigest()
        to_hash=hashlib.sha256(login_to.encode('utf-8')).hexdigest()
        token=hashlib.sha256((from_hash+to_hash).encode('utf-8')).hexdigest()
        if not(os.path.exists(self.users+"/"+to_hash+".block")):
            return None
        f=open(self.connections+"/"+from_hash+".block")
        conn=f.read()
        f.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        keyv = hashlib.sha256(from_hash.encode('utf-8')).hexdigest()
        key = base64.urlsafe_b64encode(kdf.derive(bytes(keyv, encoding='utf-8')))
        fern = Fernet(key)
        conn=fern.decrypt(conn.encode('utf-8')).decode('utf-8')
        conn=json.decoder.JSONDecoder().decode(conn)
        if not(login_to in conn["users"]):
            f = open(self.connections +"/"+ from_hash + ".block", 'w')
            conn["users"].append(login_to)
            f.write(fern.encrypt(bytes(json.dumps(conn), encoding='utf-8')).decode('utf-8'))
            f.close()

        f = open(self.connections + "/"+to_hash + ".block")
        conn = f.read()
        f.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        keyv = hashlib.sha256(to_hash.encode('utf-8')).hexdigest()
        key = base64.urlsafe_b64encode(kdf.derive(bytes(keyv, encoding='utf-8')))
        fern = Fernet(key)
        conn = fern.decrypt(conn.encode('utf-8')).decode('utf-8')
        conn = json.decoder.JSONDecoder().decode(conn)
        if not (login_from in conn["users"]):
            f = open(self.connections +"/"+ to_hash + ".block", 'w')
            conn["users"].append(login_from)
            f.write(fern.encrypt(bytes(json.dumps(conn), encoding='utf-8')).decode('utf-8'))
            f.close()

        message = {
            "user_from": "",
            "user_to": "",
            "message": "",
            "date": "",
            "time": "",
            "hash_before": "0",
            "code": "0"
        }
        message["user_from"] = login_from
        message["user_to"] = login_to
        message["message"]=message1
        message["time"]=str(time.strftime("%H:%M:%S", time.localtime()))
        message["date"]=str(datetime.date.today())

        if not(os.path.exists(self.messages + "/" + to_hash + "/" + from_hash)):
            os.mkdir(self.messages + "/" + to_hash + "/" + from_hash)
            f=open(self.messages + "/" + to_hash + "/" + from_hash+"/"+"config.block", 'w')
            f.write("0")
            f.close()
        f=open(self.messages + "/" + to_hash + "/" + from_hash+"/"+"config.block")
        hash_past_to=f.read()
        f.close()
        i = 0
        while True:
            message["hash_before"] = str(hash_past_to)
            message["code"]=str(i)
            hash_of_message = hashlib.sha256(json.dumps(message).encode('utf-8')).hexdigest()
            if not(os.path.exists(self.messages + "/" + to_hash + "/" + from_hash+"/"+hash_of_message+".block")):
                f = open(self.messages + "/" + to_hash + "/" + from_hash + "/" + hash_of_message+".block", 'w')
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=100000,
                    backend=backend
                )
                token=hashlib.sha256((to_hash+from_hash).encode('utf-8')).hexdigest()
                key = base64.urlsafe_b64encode(kdf.derive(
                    bytes(hashlib.sha256(token.encode('utf-8')).hexdigest(), encoding='utf-8')))
                fern = Fernet(key)
                f.write(fern.encrypt(bytes(json.dumps(message), encoding='utf-8')).decode('utf-8'))
                f.close()

                f = open(self.messages + "/" + to_hash + "/" + from_hash + "/" + "config.block", 'w')
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=100000,
                    backend=backend
                )
                token = hashlib.sha256((to_hash + from_hash).encode('utf-8')).hexdigest()
                key = base64.urlsafe_b64encode(kdf.derive(
                    bytes(str(hashlib.sha256(token.encode('utf-8')).hexdigest()), encoding='utf-8')))
                fern = Fernet(key)
                f.write(fern.encrypt(bytes(hash_of_message, encoding='utf-8')).decode('utf-8'))
                f.close()
                break
            else:
                i+=1
        if not(os.path.exists(self.messages + "/" + from_hash + "/" + to_hash)):

            os.mkdir(self.messages + "/" + from_hash + "/" + to_hash)
            f=open(self.messages + "/" + from_hash + "/" + to_hash+"/"+"config.block", 'w')
            f.write("0")
            f.close()
        f=open(self.messages + "/" + from_hash + "/" + to_hash+"/"+"config.block",)
        hash_past_from=f.read()
        f.close()
        i = 0
        while True:
            message["hash_before"] = str(hash_past_from)
            message["code"]=str(i)
            hash_of_message = hashlib.sha256(json.dumps(message).encode('utf-8')).hexdigest()
            if not(os.path.exists(self.messages + "/" + from_hash + "/" + to_hash+"/"+hash_of_message+".block")):
                f = open(self.messages + "/" + from_hash + "/" + to_hash + "/" + hash_of_message+".block", 'w')
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=100000,
                    backend=backend
                )
                token = hashlib.sha256((from_hash + to_hash).encode('utf-8')).hexdigest()
                key = base64.urlsafe_b64encode(kdf.derive(
                    bytes(str(hashlib.sha256(token.encode('utf-8')).hexdigest()), encoding='utf-8')))
                fern = Fernet(key)
                f.write(fern.encrypt(bytes(json.dumps(message), encoding='utf-8')).decode('utf-8'))
                f.close()
                f = open(self.messages + "/" + from_hash + "/" + to_hash + "/" + "config.block", 'w')

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=100000,
                    backend=backend
                )
                token = hashlib.sha256((from_hash + to_hash).encode('utf-8')).hexdigest()
                key = base64.urlsafe_b64encode(kdf.derive(
                    bytes(str(hashlib.sha256(token.encode('utf-8')).hexdigest()), encoding='utf-8')))
                fern = Fernet(key)
                f.write(fern.encrypt(bytes(hash_of_message, encoding='utf-8')).decode('utf-8'))
                f.close()
                break
            else:
                i+=1

    def sign_in(self, login, password):
        log_hash = hashlib.sha256(login.encode('utf-8')).hexdigest()
        pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(bytes(str(hashlib.sha256((password + pw_hash).encode('utf-8')).hexdigest()), encoding='utf-8')))
        fern = Fernet(key)
        if not(os.path.exists(self.users + "/" + log_hash+".block")):
            return None
        f=open(self.users + "/" + log_hash+".block")
        data=f.read()
        f.close()
        data=bytes(data, encoding='utf-8')
        data=fern.decrypt(data).decode('utf-8')
        user=json.decoder.JSONDecoder().decode(data)
        if pw_hash==user["pw_hash"]:
            return user["token"]
        return None
    def get_messages(self, user1, user2, token, count): #count - count messages for getting, token - token of first user
        copy_token=token
        user1=hashlib.sha256(user1.encode('utf-8')).hexdigest()
        user2=hashlib.sha256(user2.encode('utf-8')).hexdigest()
        f=open(self.users+"/"+user1+".block")
        user=f.read()
        f.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(bytes(token, encoding='utf-8')))
        fern = Fernet(key)
        user = bytes(user, encoding='utf-8')
        user = fern.decrypt(user).decode('utf-8')
        try:
            user = json.decoder.JSONDecoder().decode(user)
            if(not(user["token"]==copy_token)):
                return None
        except Exception as e:
            return None
        messages=list()
        path=self.messages+"/"+user1+"/"+user2+"/"
        if not(os.path.exists(path)):
            return None
        name_past=path+"config.block"
        f=open(name_past)
        name_past=f.read()
        f.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        token=hashlib.sha256((user1+user2).encode('utf-8')).hexdigest()
        key = base64.urlsafe_b64encode(
            kdf.derive(bytes(hashlib.sha256(token.encode('utf-8')).hexdigest(), encoding='utf-8')))
        fern = Fernet(key)
        name_past = bytes(name_past, encoding='utf-8')
        name_past = fern.decrypt(name_past).decode('utf-8')
        for i in range(count):
            f=open(path+name_past+".block")
            data=f.read()
            f.close()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=backend
            )
            token = hashlib.sha256((user1 + user2).encode('utf-8')).hexdigest()
            key = base64.urlsafe_b64encode(
                kdf.derive(bytes(hashlib.sha256(token.encode('utf-8')).hexdigest(), encoding='utf-8')))
            fern = Fernet(key)
            data = bytes(data, encoding='utf-8')
            data = fern.decrypt(data).decode('utf-8')
            message=json.decoder.JSONDecoder().decode(data)
            messages.append(message)
            if message["hash_before"]=="0":
                return messages
            name_past=bytes(message["hash_before"], encoding='utf-8')
            name_past = fern.decrypt(name_past).decode('utf-8')
        return messages
    def get_user_data(self, login, token):
        login=hashlib.sha256(login.encode('utf-8')).hexdigest()
        f=open(self.users+"/"+login+".block")
        data=f.read()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        try:
            key = base64.urlsafe_b64encode(
                kdf.derive(bytes(token, encoding='utf-8')))
            fern = Fernet(key)
            data = bytes(data, encoding='utf-8')
            data = fern.decrypt(data).decode('utf-8')
            data = json.decoder.JSONDecoder().decode(data)
            return data["data"]
        except Exception as e:
            return None

    def set_user_data(self, login, token, data1):
        login=hashlib.sha256(login.encode('utf-8')).hexdigest()
        f=open(self.users+"/"+login+".block")
        data=f.read()
        f.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        try:
            key = base64.urlsafe_b64encode(
                kdf.derive(bytes(token, encoding='utf-8')))
            fern = Fernet(key)
            data = bytes(data, encoding='utf-8')
            data = fern.decrypt(data).decode('utf-8')
            data = json.decoder.JSONDecoder().decode(data)
            data["data"] = data1
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=backend
            )
            key = base64.urlsafe_b64encode(kdf.derive(
                bytes(token, encoding='utf-8')))
            fern = Fernet(key)
            f = open(self.users + "/" + login + ".block", 'w')
            f.write(fern.encrypt(bytes(json.dumps(data), encoding='utf-8')).decode('utf-8'))
            f.close()
            return 0
        except Exception as e:
            print(e)
            return None
    def get_connections(self, login, token):
        from_hash=hashlib.sha256(login.encode('utf-8')).hexdigest()
        f = open(self.connections +"/"+ from_hash + ".block")
        conn = f.read()
        f.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=backend
        )
        keyv = hashlib.sha256(from_hash.encode('utf-8')).hexdigest()
        key = base64.urlsafe_b64encode(kdf.derive(bytes(keyv, encoding='utf-8')))
        fern = Fernet(key)
        conn = fern.decrypt(conn.encode('utf-8')).decode('utf-8')
        return json.JSONDecoder().decode(conn)["users"]

    def is_exist(self, login, token):
        log_hash=hashlib.sha256(login.encode('utf-8')).hexdigest()
        if not(os.path.exists(self.users+"/"+log_hash+".block")):
            return False
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=backend
            )
            key = base64.urlsafe_b64encode(kdf.derive(bytes(token, encoding='utf-8')))
            fern = Fernet(key)
            f=open(self.users+"/"+log_hash+".block")
            data=f.read()
            f.close()
            data=fern.decrypt(data.encode('utf-8')).decode('utf-8')
            data=json.JSONDecoder().decode(data)
            if data["token"]==token:
                return True
            return False
        except Exception as e:
            return False
    def get_users(self):
        f=open(self.public_data)
        data=f.read().split("; ")
        f.close()
        if len(data)>0:
            data.pop(0)
        return data