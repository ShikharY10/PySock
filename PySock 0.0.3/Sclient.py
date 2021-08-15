import os
import socket
import base64
import pickle
import threading
import multiprocessing
import hashlib
import random
import yaml
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class IPNC():

    def __init__(self):
        pass

    def read_yml(self,file = None):

        with open(file) as file:
            documents = yaml.full_load(file)
            return documents

    def write_yml(self,file = None, dict_data = None,mode = "a+"):

        with open(file, mode) as file:
            yaml.dump(dict_data, file)

    def add_node(self,file = None, node = None):
        try:
            read = self.read_yml(file)
            if read != None:
                read[node[0]]
                self.change_node_value(file,node)
            else:
                raise KeyError
        except KeyError:
            node_dict = {
                node[0] : node[1]
            }
            self.write_yml(file, node_dict)

    def change_node_value(self,file = None, node = None):
        r_yml = self.read_yml(file)
        r_yml[node[0]] = node[1]
        self.write_yml(file = file, dict_data = r_yml, mode = "w")

    def get_node(self,file = None, key = None, wait = True):
        # print(key)
        if key == None:
            return self.read_yml(file)
        
        if wait:
            while True:
                r_yml = self.read_yml(file)
                try:
                    value = r_yml[key]
                    return value
                except KeyError:
                    # print("key not found")
                    pass

                except TypeError:
                    pass
        else:
            r_yml = self.read_yml(file)
            try:
                value = r_yml[key]
                return value
            except KeyError:
                # print("key not found")
                return None

            except TypeError:
                pass

    def remove_node(self,file,node):
        try:
            r_yml = self.read_yml(file = file)
            r_yml[node]
            r_yml.pop(node)
            self.write_yml(file = file, dict_data = r_yml, mode = "w")
            
        except KeyError:
            print("key not found")
            #pass
        except:
            pass

    def name_generator(self,_len_ = 16, onlyText = False):
        lower_case = list("abcdefghijklmnopqrstuvwxyz")
        upper_case = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        special = list("!@#$%&*?")
        number = list("0123456789")

        if onlyText:
            _all_ = lower_case + upper_case
        else:
            _all_ = lower_case + upper_case + special + number
            
        random.shuffle(_all_)
        return "".join(random.sample(_all_,_len_))

    def code001_AN(self,file = None, key = None ,target_key = None, value = None, first_time = False):
        read = self.get_node(
            file = file,
            key = key,
            wait = False
        )

        if read is not None:
            read[target_key] = value

            self.add_node(
                file = file,
                node = [
                    key,
                    read
                ]
            )
        else:
            self.add_node(
                file = file,
                node = [
                    key,
                    {target_key : value}
                ]
            )
        
    def code001_UN(self,file = None, key = None, target_key = None, position : int = None, value = None):
        read = self.get_node(
            file = file,
            key = key,
            wait = False
        )
        if read is not None:

            if position == None:
                read[target_key] = value
            else:
                base = read[target_key]
                base.pop(position)
                base.insert(position,value)
                read[target_key] = base

            self.add_node(
                file = file,
                node = [
                    key,
                    read
                ]
            )

class DspError(Exception):
    def __init__(self,err_msg):
        print(err_msg)

class Main(IPNC):

    def __init__(self,client_name : str = None, file : str = None, debug : bool = False, rememberServer = True, MPCL : bool = False, MTCL : bool = True):
        
        IPNC.__init__(self)

        self.__debug = debug

        if not file:
            raise TypeError("__init__() missing 1 required positional argument: 'file'")
        else:
            self.__file_location = file
            # self.__client_name = hashlib.sha256(bytes(client_name,"utf-8")).digest()
            self.__client_name = client_name

        if MPCL and MTCL:
            raise ValueError("both 'MPCL' abd 'MTCL' should not be set to True")

        elif not MPCL and not MTCL:
            raise ValueError("both 'MPCL' abd 'MTCL' should not be set to False")

        else:
            self.__MPCL = MPCL
            self.__MTCL = MTCL

        self.__CUSTOM_CHANNEL = []
        self.__MESSAGE_HANDLER = []
        self.__CALLBACK_LOOP = []
        self.__SENDER_QUEUE = []
        self.HS_Devices = []
        self.__KEY_STORE ={}

        if rememberServer:

            __get = self.get_node(file = self.__file_location,key = hashlib.sha256(bytes("__VARIFIED", "utf-8")).digest(), wait = False)
          
            if __get == None:
                self.add_node(
                    file=self.__file_location,
                    node=[
                        hashlib.sha256(bytes("__VARIFIED", "utf-8")).digest(),
                        pickle.dumps(False)
                    ]
                )

            __code003_hs_key = self.get_node(
                file = self.__file_location,
                key = "key",
                wait = False
            )

            if __code003_hs_key is not None:
                # print(f"__code003_hs_key : {__code003_hs_key}")

                self.__KEY_STORE = __code003_hs_key

                self.HS_Devices = [k for (k,v) in __code003_hs_key.items() if v[0] == "varified"]


            __code001_key = self.get_node(
                file = self.__file_location,
                key = "code_001_srt_key",
                wait = False
            )

            if __code001_key is not None:
                if __code001_key["status"] == "varified":
                    self.__KEY_STORE["code_001_srt_key"] = __code001_key["key"]

        self.__CUSTOM_CHANNEL.append("DSP_MSG")
        self.__VARIFIED = self.get_node(
            file = self.__file_location,
            key = hashlib.sha256(bytes("__VARIFIED", "utf-8")).digest(),
            wait = False
        )
        self.__VARIFIED = pickle.loads(self.__VARIFIED)

    def __load_object(self, data = None, secure : bool = True, key_dict : bytes = None):
        if not data:
            raise TypeError("__load_object() missing one positional argument 'data'")
        if secure:
            if not key_dict:
                raise TypeError("__load_object() missing one positional argument 'key_dict', it is compulsory when secure is set to True")
            else:
                pass

        loaded = pickle.loads(base64.b64decode(data))

        if loaded["secure"] and secure:

            key_pack = pickle.loads(base64.b64decode(key_dict["code_001_srt_key"]))

            aes_gcm = AESGCM(key_pack["aes_key"])
            decryptedtext = aes_gcm.decrypt(
                nonce = key_pack["nonce"],
                data = loaded["data"],
                associated_data = key_pack["aad"]
            )

            unflatted = pickle.loads(base64.b64decode(decryptedtext))

            return unflatted

        elif not secure and not loaded["secure"]:

            unflatted = pickle.loads(base64.b64decode(loaded["data"]))

            return unflatted

    def __serializer(self, object = None, secure : bool = True, key_dict : bytes = None):

        if not object:
            raise TypeError("__load_object() missing one positional argument 'data'")
        else:
            if type(object) != type({1:"a"}):
                raise TypeError(f"__serializer() 'object' argument should be of type {type({'a':1})}")
        if secure:
            if not key_dict:
                raise TypeError("__load_object() missing one positional argument 'key_dict', it is compulsory when secure is set to True")

        # target = object["target_name"]
        normalize = base64.b64encode(pickle.dumps(object))

        if secure:

            key_pack = pickle.loads(base64.b64decode(key_dict["code_001_srt_key"]))

            aes_gcm = AESGCM(key_pack["aes_key"])
            cyphertext = aes_gcm.encrypt(
                nonce = key_pack["nonce"],
                data = normalize,
                associated_data = key_pack["aad"]
            )

            prepare_serialized_data = {"secure" : secure, "sender_name" : self.__client_name, "data" : cyphertext}
            flatten_psd = base64.b64encode(pickle.dumps(prepare_serialized_data))

            return flatten_psd
        else:

            prepare_serialized_data = {"secure" : secure, "sender_name" : self.__client_name, "data" : normalize}
            flatten_psd = base64.b64encode(pickle.dumps(prepare_serialized_data))

            return flatten_psd
    
    def CLIENT(self,address : str = None, port : int = None,timeout : int = 1):
        
        if self.__debug:
            print("[Connecting TO Server]")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((address, port))

        if self.__debug:
            print("[Connected]")

        
        receiver_thread = threading.Thread(target=self.__receiver)

        sender_thread = threading.Thread(
            target = self.__sender,
            args = (self.sock, self.__SENDER_QUEUE)
        )

        if self.__MTCL:
            callback_loop_thread_process = threading.Thread(
                target = self.__callback_lopp,
                args = (self.__CALLBACK_LOOP,)
            )
        else:
            callback_loop_thread_process = multiprocessing.Process(
                target = self.__callback_loop,
                args = (self.__CALLBACK_LOOP,)
            )

        receiver_thread.daemon = True
        sender_thread.daemon = True
        callback_loop_thread_process.daemon = True

        receiver_thread.start()
        sender_thread.start()
        callback_loop_thread_process.start()

        if not self.__VARIFIED:

            code_001_srt_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            code_001_key = code_001_srt_key.public_key()
            str_code_001_key = code_001_key.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            ).decode()

            OBJECT = self.__serializer(
                    object = {"type" : "code-1.0.0-new", "username" : self.__client_name, "data" : str_code_001_key},
                    secure = False
                )

            self.sock.send(str(len(OBJECT)).center(16,"|").encode("utf-8"))
            self.sock.send(OBJECT)

            # self.code001_AN(
            #     file = self.__file_location,
            #     key = "code_001_srt_key",
            #     target_key = 
            # )

            self.add_node(
                file = self.__file_location,
                node = [
                    # hashlib.sha256(bytes("code_001_srt_key","utf-8")).digest(),
                    "code_001_srt_key",
                    {
                        "status" : "unvarified",
                        "key" : code_001_srt_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(
                            b'aw56hfseyinhy7fce4ser')
                    )
                    }
                ]
            )

            count_time = datetime.datetime.now() + datetime.timedelta(minutes = timeout)
            while datetime.datetime.now() <= count_time and not self.__VARIFIED:
                pass
                
            if not self.__VARIFIED:
                raise TimeoutError("could not varified by server, try again!")
        else:

            OBJECT = self.__serializer(
                    object = {"type" : "_", "username" : self.__client_name, "data" : ""},
                    secure = False
                )

            self.sock.send(str(len(OBJECT)).center(16,"|").encode("utf-8"))
            self.sock.send(OBJECT)    

    def __receiver(self):
        while True:
            if not self.__VARIFIED:
                data_len = int(self.sock.recv(16).decode().strip("|"))
                if not data_len:
                    self.sock.close()
                    # pair -a1.1
                    #need future attention----------------------------------------------------------------------

                else:
                    recv_data = self.sock.recv(data_len)

                    _info = self.__load_object(
                        data = recv_data,
                        secure = False
                    )
                    # print(f"_info_ : {_info}")

                    # _info = {"type" = "code-0.0.1-key-res", "sender_name" : "SERVER", "data" : "encrypted aes key pack"}

                    if _info["type"] == "code-1.1.0-new" and _info["sender_name"] == "SERVER":

                        code001_key_load = self.get_node(
                            file = self.__file_location,
                            # key = hashlib.sha256(bytes("code_001_srt_key","utf-8")).digest()
                            key = "code_001_srt_key"
                        )

                        # print(code001_key_load)

                        if code001_key_load["status"] == "unvarified":

                            code_001_srt_key = serialization.load_pem_private_key(
                                data = code001_key_load["key"],
                                password=b'aw56hfseyinhy7fce4ser',
                                backend=default_backend()
                            )

                            key_pack = code_001_srt_key.decrypt(
                                ciphertext = _info["data"],
                                padding = padding.OAEP(
                                    mgf = padding.MGF1(
                                        algorithm = hashes.SHA256()
                                    ),
                                    algorithm = hashes.SHA256(),
                                    label = None
                                )
                            )

                            self.add_node(
                                file = self.__file_location,
                                node = [
                                    # hashlib.sha256(bytes("code_001_srt_key","utf-8")).digest(),
                                    "code_001_srt_key",
                                    {
                                        "status" : "varified",
                                        "key" : key_pack
                                    }
                                ]
                            )

                            self.__KEY_STORE["code_001_srt_key"] = key_pack

                            OBJECT = {
                                "type" : "code-1.1.1-new",
                                "sender_name" : self.__client_name,
                                "target_name" : "SERVER",
                                "data" : hashlib.sha256(bytes("saved","utf-8")).digest()
                            }

                            normalized = self.__serializer(
                                object = OBJECT,
                                secure = True,
                                key_dict = self.__KEY_STORE
                            )

                            self.__SENDER_QUEUE.append(normalized)

                            self.__VARIFIED = True

                            self.add_node(
                                file = self.__file_location,
                                node=[
                                    hashlib.sha256(
                                        bytes("__VARIFIED", "utf-8")).digest(),
                                    pickle.dumps(True)
                                ]
                            )

            else:
                data_len = int(self.sock.recv(16).decode().strip("|"))
                if not data_len:
                    self.sock.close()
                    # pair -a1.2
                else:
                    recv_data = self.sock.recv(data_len)
                    code_002 = self.__load_object(
                        data = recv_data,
                        secure = True,
                        key_dict = self.__KEY_STORE
                    )

                    # code_002 = {"type" = "xyz", "bypass-pipe" : "SERVER", "sender_name" : "xyz", "target_name" : "abc", "data" : "pqr"}
                    # handshake counter part
                    if code_002["type"] == "DSP_REQ":

                        if code_002["target_name"] == self.__client_name:

                            M_code002_k_pack = {
                                "aes_key" : AESGCM.generate_key(256),
                                "nonce"  : os.urandom(32),
                                "aad" : bytes(self.name_generator(),"utf-8"),
                                "approved" : True
                            }
                            normalized_M_code002_k_pack = base64.b64encode(pickle.dumps(M_code002_k_pack))

                            rsa_key =load_ssh_public_key(
                                bytes(code_002["data"],"utf-8"),
                                backend=default_backend()
                            )


                            ciphertext = rsa_key.encrypt(
                                normalized_M_code002_k_pack,
                                padding.OAEP(
                                    mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                    algorithm = hashes.SHA256(),
                                    label = None
                                )
                            )

                            OBJECT = {
                                "type" : "DSP_HR-L1",
                                "bypass-pipe" : "SERVER",
                                "sender_name" : self.__client_name,
                                "target_name" : code_002["sender_name"],
                                "data" : ciphertext
                            }

                            normalized = self.__serializer(
                                object = OBJECT,
                                secure = True,
                                key_dict = self.__KEY_STORE
                            )

                            self.__SENDER_QUEUE.append(normalized)

                            del M_code002_k_pack["approved"]

                            code001_AN_value = base64.b64encode(pickle.dumps(M_code002_k_pack))

                            self.code001_AN(
                                file = self.__file_location,
                                key = "key",
                                target_key  = code_002["sender_name"],
                                value = ["unvarified",code001_AN_value]
                            )

                            self.__KEY_STORE[code_002["sender_name"]] = ["unvarified",code001_AN_value]
                            
                            if self.__debug:
                                print(f"HS from : {code_002['sender_name']} | step_1 Done")

                    # code_002 = {"type" = "xyz", "bypass-pipe" : "SERVER", "sender_name" : "xyz", "target_name" : "abc", "data" : "pqr"}
                    # type DSP-HR counter part
                    elif code_002["type"] == "DSP_HR-L1":

                        if code_002["target_name"] == self.__client_name:

                            flatten_key = pickle.loads(base64.b64decode(self.__KEY_STORE[code_002["sender_name"]]))[1]
                            
                            loaded_code_003_srt = serialization.load_pem_private_key(
                                data = flatten_key,
                                password = b'oieffjwouifh2398r29r8238h38h923h8983',
                                backend = default_backend()
                            )

                            __code_003_aes_srt = loaded_code_003_srt.decrypt(
                                ciphertext = code_002["data"],
                                padding = padding.OAEP(
                                    mgf = padding.MGF1(
                                        algorithm = hashes.SHA256()
                                    ),
                                    algorithm = hashes.SHA256(),
                                    label = None
                                )
                            )

                            __code_003_aes_srt = pickle.loads(base64.b64decode(__code_003_aes_srt))
                            
                            if __code_003_aes_srt["approved"]:

                                OBJECT = {
                                    "type" : "DSP_HR-L2",
                                    "bypass-pipe" : "SERVER",
                                    "sender_name" : self.__client_name,
                                    "target_name" : code_002["sender_name"],
                                    "data" : hashlib.sha256(bytes("approved","utf-8")).digest()

                                }

                                del __code_003_aes_srt['approved']

                                __code_003_aes_srt = base64.b64encode(pickle.dumps(__code_003_aes_srt))
                                                                
                                normalized = self.__serializer(
                                    object = OBJECT,
                                    secure = True, 
                                    key_dict = self.__KEY_STORE
                                )

                                self.__SENDER_QUEUE.append(normalized)

                                self.code001_UN(
                                    file = self.__file_location,
                                    key = "key",
                                    target_key = code_002["sender_name"],
                                    position = None,
                                    value = ["varified",__code_003_aes_srt]
                                )

                                self.__KEY_STORE[code_002["sender_name"]] = base64.b64encode(pickle.dumps(["varified",__code_003_aes_srt]))
                                self.HS_Devices.append(code_002["sender_name"])

                                print("Done")

                    # "DSP-HRR-L1" counter part
                    elif code_002["type"] == "DSP_HR-L2":
                        if code_002["target_name"] == self.__client_name:
                            if code_002["data"] == hashlib.sha256(bytes("approved","utf-8")).digest():

                                self.code001_UN(
                                    file = self.__file_location,
                                    key = "key",
                                    target_key = code_002["sender_name"],
                                    position = 0,
                                    value = "varified"
                                )

                                self.__KEY_STORE[code_002["sender_name"]] = base64.b64encode(pickle.dumps(
                                            [
                                                "varified",
                                                self.__KEY_STORE[code_002["sender_name"]][1]
                                            ]
                                        )
                                    )
                                

                                self.HS_Devices.append(code_002["sender_name"])

                                print(f"Handshake from {code_002['sender_name']} Done")

                    elif code_002["type"] == "DSP_MSG":
                        code_004_key = self.__KEY_STORE[code_002["sender_name"]]
                        code_004_key = pickle.loads(base64.b64decode(code_004_key[1]))
                        aes_gcm = AESGCM(code_004_key["aes_key"])
                        decryptedtext = aes_gcm.decrypt(
                            nonce = code_004_key["nonce"], 
                            data = code_002["data"],
                            associated_data = code_004_key["aad"]
                        )
                        data = pickle.loads(base64.b64decode(decryptedtext))
                        code_002["data"] = data
                        self.__MESSAGE_HANDLER.append(code_002)

                    elif code_002["type"] in self.__CUSTOM_CHANNEL:
                        self.__MESSAGE_HANDLER.append(code_002)

                    
            

    def __sender(self, sock, __sender_queue):
        while True:
            for i,data in enumerate(__sender_queue):
                sock.send(str(len(data)).center(16,"|").encode("utf-8"))
                sock.send(data)
                __sender_queue.pop(i)

    def __callback_lopp(self,__callback_lst):
        while True:
            for i,func in enumerate(__callback_lst):
                __callback_lst.pop(i)
                func[0](*func[1])

    def CREATE_CHANNEL(self, channels : str = None, multiple : bool = False):
        if not multiple:
            if type[channels] == type([]):
                raise ValueError("'channels' should be a string when multiple is set to False.")

        if multiple:
            if type(channels) is type([]):
                for channel in channels:
                    if channel not in self.__CUSTOM_CHANNEL:
                        self.__CUSTOM_CHANNEL.append(channel)
        else:
            if channels not in self.__CUSTOM_CHANNEL:
                self.__CUSTOM_CHANNEL.append(channels)

    def HANDSHAKE(self,target_name : str = None):

        if self.__debug:
            print("Doing Handshake...")
            
        # target_name = hashlib.sha256(target_name).digest()

        try:
            check = self.__KEY_STORE[target_name]
        except KeyError:
            check = None

        if check is not None:

            if len(check) > 0 or check is None:
                if self.__debug:
                    print(f"{target_name} : already handshaked OR have the request for handshake.")

        else:
            __code_002_srt_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            __code_002_pub_key = __code_002_srt_key.public_key()
            str_code_002_pub_key = __code_002_pub_key.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            ).decode()

            # print(f"str_code_002_pub_key : {str_code_002_pub_key}") #===============

            OBJECT = {
                "type" : "DSP_REQ",
                "bypass_pipe" : "SERVER",
                "sender_name" : self.__client_name,
                "target_name" : target_name,
                "data" : str_code_002_pub_key
                }

            normalised = self.__serializer(
                object = OBJECT,
                secure = True,
                key_dict = self.__KEY_STORE
            )

            self.__SENDER_QUEUE.append(normalised)

            __code_003_srt_key_str = __code_002_srt_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    b'oieffjwouifh2398r29r8238h38h923h8983')
            )

            self.code001_AN(
                file = self.__file_location,
                key = "key",
                target_key = target_name,
                value = [
                    "unvarified",
                    __code_003_srt_key_str
                ]
            )
            self.__KEY_STORE[target_name] = base64.b64encode(pickle.dumps(["unvarified",__code_003_srt_key_str]))

            if self.__debug:
                print("Handshake Request Send.")

        

    def LISTEN(self,channel : str = None, function : object = None, args = None):
        
        if not channel:
            raise TypeError("LISTEN() missing 1 required positional argument: 'channel'")
        else:
            found = False
            index = None

            if channel in self.__CUSTOM_CHANNEL:
                for i,d in enumerate(self.__MESSAGE_HANDLER):
                    if d["type"] == channel:
                        found = True
                        index = i
                        break
                
                if found:
                    if not args:
                        p_data = self.__MESSAGE_HANDLER.pop(index)
                        self.__CALLBACK_LOOP.append([function,[p_data]])
                    else:
                        p_data = self.__MESSAGE_HANDLER.pop(index)
                        args = list(args)
                        args.insert(0,p_data)
                        self.__CALLBACK_LOOP.append([function,args])

    def SEND(self,channel : str = None, data = None):

        if not channel:
            raise TypeError("SEND() missing 1 required positional argument: 'channel'")
        if not data:
            raise TypeError("SEND() missing 1 required positional argument: 'data'")

        lst = [ [1,2], {"a":1}, (1,2), {1,2,}, "a", 12, 0.45, b"bytes" ]
        allowed_lst= []

        for l in lst:
            allowed_lst.append(type(l))

        if type(data) in allowed_lst:
            if channel in self.__CUSTOM_CHANNEL:

                prepare_send_data = {
                    "type" : channel,
                    "bypass-pipe" : "SERVER",
                    "sender_name" : self.__client_name,
                    "target_name" : "SERVER",
                    "data" : data
                }

                normalized = self.__serializer(
                    object = prepare_send_data,
                    secure = True,
                    key_dict = self.__KEY_STORE
                )

                self.__SENDER_QUEUE.append(normalized)
        else:
            raise TypeError(f"unallowed / untransmitable type of argument 'data', {type(data)}")

    def SEND_TO_CLIENT(self, target_name : str = None, data = None):

        if not target_name:
            raise TypeError("SEND() missing 1 required positional argument: 'target_name'")
        if not data:
            raise TypeError("SEND() missing 1 required positional argument: 'data'")

        lst = [ [1,2], {"a":1}, (1,2), {1,2,}, "a", 12, 0.45, b"bytes" ]
        allowed_lst= []
        for l in lst:
            allowed_lst.append(type(l))
        
        if type(data) in allowed_lst:

                try:
                    code_004_key = self.__KEY_STORE[target_name]
                except KeyError:
                    raise DspError(f"{target_name} is not  registered/ handshaked client")

                if code_004_key[0] == "varified":
                    __code_004_srt_key = pickle.loads(base64.b64decode(code_004_key[1]))

                    aes_gcm = AESGCM(__code_004_srt_key["aes_key"])
                    ciphertext = aes_gcm.encrypt(
                        nonce = __code_004_srt_key["nonce"],
                        data = base64.b64encode(pickle.dumps(data)),
                        associated_data = __code_004_srt_key["aad"]
                    )

                    OBJECT = {
                        "type" : "DSP_MSG",
                        "bypass-pipe" : "SERVER",
                        "target_name" : target_name,
                        "sender_name" : self.__client_name,
                        "data" : ciphertext
                    }

                    normalized = self.__serializer(
                        object = OBJECT,
                        secure = True,
                        key_dict = self.__KEY_STORE
                    )

                    self.__SENDER_QUEUE.append(normalized)
        else:
            raise TypeError(f"unallowed / untransmitable type of argument 'data', {type(data)}")

class Sclient():

    def __init__(self,client_name : str = None, file : str = None, debug : bool = False, rememberServer = True, MPCL : bool = False, MTCL : bool = True):
        
        __parent  = Main(client_name,file,debug, rememberServer, MPCL,MTCL)

        self.CLIENT = __parent.CLIENT
        self.HS_Devices = __parent.HS_Devices
        self.CREATE_CHANNEL = __parent.CREATE_CHANNEL
        self.LISTEN = __parent.LISTEN
        self.HANDSHAKE = __parent.HANDSHAKE
        self.SEND = __parent.SEND
        self.SEND_TO_CLIENT = __parent.SEND_TO_CLIENT

