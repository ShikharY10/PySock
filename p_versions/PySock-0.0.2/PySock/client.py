# @package name - asyncSocket
# @os - independent
# @auther - Shikhar Yadav | yshikharfzd10@gmail.com
__all__ = ["client"] 

#import
from typing import Any
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import socket
import threading
import sys
import pickle
import base64
import os
import hashlib
import yaml
import random
import datetime

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

class DSP():

    def __init__(
        self,
        msg: str = None,
        DSP_type: str = None,
        device_id: int = None,
        universalAesKey: bytes = None,
        nonce: bytes = None,
        aad: str = None,
    ):

        if msg is not None:
            self.msg = msg
        else:
            self.msg = msg

        self.DSP_type = DSP_type
        self.device_id = device_id

        if universalAesKey is not None:
            self.UNIVERSAL_AES_KEY = universalAesKey
        else:
            self.UNIVERSAL_AES_KEY = b't\x89\xcc\x87\xcca\xe8\xfb\x06\xed\xcf+\x0eVB\xd2\xd3\xbeMk\xfa\xd1J\xa7\xc8@\xf8\x05\x0f\xfc\x18\x00'

        if nonce is not None:
            self.NONCE = nonce
        else:
            self.NONCE = b'\xfe\x1e1\xc0\xfc`s\xbc6\x9fQ\xb2'

        if aad is not None:
            self.AAD = aad
        else:
            self.AAD = b"au$tica&tedbut@u32nencr#cdscypteddatafdrj"

    def edit_file(self, indentifier, to_edit, value=None):
        lines = []
        with open("client_1.py") as f:
            lines = f.readlines()
        if value is not None:
            change_pattern = f"{to_edit} = {value}\n"
        else:
            change_pattern = f"{to_edit}\n"
        if indentifier in lines:
            index_identifier = lines.index(indentifier)
            lines.remove(indentifier)
            lines.insert(index_identifier, change_pattern)
            f = open("asyncClient.py", "w")
            for line in lines:
                f.write(line)
            with open("asyncClient.py", "a") as f:
                f.write("")
        else:
            print("No Match Found!")

    def messanger(self, MSG=None, secure: bool = True, secure_dict: bytes = None):
        if MSG is not None:
            self.msg = MSG
        # try:
        if secure:
            if secure_dict is None:
                raise TypeError("Error")
            else:
                secure_dict = pickle.loads(base64.b64decode(secure_dict))

            data = f'DSP("{self.msg}","{self.DSP_type}")'
            data = pickle.dumps(data)
            aesgcm = AESGCM(secure_dict["aes_key"])
            ct = aesgcm.encrypt(
                secure_dict["nonce"],
                data,
                secure_dict["aad"]
            )
            ret = pickle.dumps([self.device_id, ct])
            ret =  base64.b64encode(ret)
            return ret
        else:
            data = f'DSP("{self.msg}","{self.DSP_type}")'
            data = pickle.dumps(data)
            encrypted_data = self.__encrypt(data)
            ret = pickle.dumps([self.device_id, encrypted_data])
            return base64.b64encode(ret)

        # except TypeError:
        #     print("Error")

        # except:
        #     pass

    def __repr__(self):
        return "_main.DSP._"

    def __encrypt(self, data):
        aesgcm = AESGCM(self.UNIVERSAL_AES_KEY,)
        ct = aesgcm.encrypt(
            self.NONCE,
            data,
            self.AAD
        )
        return ct

    def convert_to_class(self, OBJECT: bytes = None, secure: bool = True, secure_dict: bytes = None):
        OBJECT = base64.b64decode(OBJECT)
        OBJECT = pickle.loads(OBJECT)
        if secure == True:

            if secure_dict is None:
                raise TypeError(
                    "convert_to_class() missing 1 required positional argument: 'secure_lst'")
            else:
                secure_dict = pickle.loads(base64.b64decode(secure_dict))

            aesgcm = AESGCM(secure_dict["aes_key"])
            ct = aesgcm.decrypt(
                secure_dict["nonce"], OBJECT[-1], secure_dict["aad"])
            ct = pickle.loads(ct)
            return eval(ct)

        else:
            aesgcm = AESGCM(self.UNIVERSAL_AES_KEY)
            ct = aesgcm.decrypt(self.NONCE, OBJECT[-1], self.AAD)
            ct = pickle.loads(ct)
            return eval(ct)

        # except TypeError:
        #     sys.exit()

        # except ValueError:
        #     print("sender has not done the handshake")


class DSP_NOT_ENABLED(Exception):
    pass


class clientError(Exception):
    pass


class MAIN(IPNC):

    def __init__(self, client_name: str = None, DSP_enable: bool = True,file = None, debug : bool= False, rememberServer = True):

        IPNC.__init__(self)
        self.__client_init = False
        self.__file_location = file
        
        if debug:
            self.__client_name = client_name
        else:
            self.__client_name = hashlib.sha256(bytes(client_name,"utf-8")).digest()

        self.__DSP_enable = DSP_enable
        self.__debug = debug

        self.__CUSTOM_CHANNEL = []
        self.__MESSAGE_HANDLER = []
        self.__CALLBACK_LOOP = []
        self.__SENDER_QUEUE = []
        self.__KEY_STORAGE = {}
        self.HS_Devices = []
        self.EX_COUNTER = {}

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

            __keys = self.get_node(
                file = self.__file_location,
                key = "key",
                wait = False
            )

            if __keys is not None:

                for d in __keys:
                    self.__KEY_STORAGE[list(d.keys())[0]] = list(d.values())[0]

                self.HS_Devices = [ list(i.keys())[0] for i in __keys if len(list(i.values())[0]) <= 256 ]

        if DSP_enable:
            self.__CUSTOM_CHANNEL.append("DSP_MSG")

    def CLIENT(self, address: str = None, port: int = None,timeout = 1):

        self.__client_init = True

        if self.__debug:
            print("[CONNECTING TO SERVER...]")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((address, port))
        
        if self.__debug:
            print("<<CONNECTED>>")

        self.__VARIFIED = self.get_node(
            file=self.__file_location,
            key=hashlib.sha256(bytes("__VARIFIED", "utf-8")).digest()
        )
        self.__VARIFIED = pickle.loads(self.__VARIFIED)

        #thread one for sending data back data to server and other clients
        thread1 = threading.Thread(
            target=self.__sender_thread,
            args=(
                self.sock,
                self.__SENDER_QUEUE
            )
        )
        # thread two for handling the event loop which is responsible for handling multiple incoming msgs.
        thread2 = threading.Thread(
            target = self.__callback_loop,
            args = (self.__CALLBACK_LOOP,)
        )

        thread1.daemon = True
        thread2.daemon = True

        thread1.start()
        thread2.start()

        thread = threading.Thread(target = self.__receiver)
        thread.daemon = True
        thread.start()

        # secure connection
        if not self.__VARIFIED:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            public_key = private_key.public_key()
            str_public_key = public_key.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            ).decode()

            dsp_dict = {
                "username": self.__client_name,
                "data": str_public_key,
            }

            dsp_data = DSP(
                msg=dsp_dict,
                DSP_type="username_secure",
                device_id=self.__client_name,
            ).messanger(secure = False)

            self.sock.send(
                base64.b64encode(pickle.dumps([len(dsp_data)])).decode().zfill(32).encode("utf-8")
                )
            self.sock.send(
                dsp_data
            )

            self.add_node(
                file=self.__file_location,
                node=[
                    hashlib.sha256(bytes("private_key","utf-8")).digest(),
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(
                            b'aw56hfseyinhy7fce4ser')
                    )
                ]
            )

            count_time = datetime.datetime.now() + datetime.timedelta(minutes = timeout)
            while datetime.datetime.now()<= count_time and not self.__VARIFIED:
                pass
                
            if not self.__VARIFIED:
                raise TimeoutError("could not varified by server, try again!")

    def __receiver(self):
        while True:
            # try:
            # checking that the client is verified or not
            if self.__VARIFIED == False:
                data_len = int(self.sock.recv(16).decode().strip("|"))
                if not data_len:
                    self.sock.close()

                data = DSP().convert_to_class(
                    OBJECT = self.sock.recv(data_len).decode().strip(
                        "|").encode("utf-8"),
                    secure = False
                )

                if data is not None:

                    if data.DSP_type == "username_secure_response":
                        #getd = {"key" : "sacewf43f3wf3w43f34f34g"}
                        getd = eval(data.msg)

                        str_private_key = self.get_node(
                            file=self.__file_location,
                            key=hashlib.sha256(bytes("private_key","utf-8")).digest()
                        )

                        private_key = serialization.load_pem_private_key(
                            data=str_private_key,
                            password=b'aw56hfseyinhy7fce4ser',
                            backend=default_backend()
                        )
                        AES_KEY_PACK = private_key.decrypt(
                            ciphertext=base64.b64decode(getd["key"]),
                            padding=padding.OAEP(
                                mgf=padding.MGF1(
                                    algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        self.add_node(
                            file=self.__file_location,
                            node=[
                                hashlib.sha256(bytes("private_key","utf-8")).digest(),
                                AES_KEY_PACK
                            ]
                        )
                        self.__VARIFIED = True
                        self.add_node(
                            file=self.__file_location,
                            node=[
                                hashlib.sha256(
                                    bytes("__VARIFIED", "utf-8")).digest(),
                                pickle.dumps(True)
                            ]
                        )

            # if the excecution come to this 'else' statement so that means the client has been varified by the server.
            else:
                # we first take recv the length of upcoming messages and then set the buffer limit to for upcoming message
                data_len = int(self.sock.recv(16).decode().strip("|"))
                if not data_len:
                    self.sock.close()

                recv_data = self.sock.recv(data_len).decode().strip("|").encode("utf-8")
                # here we decrypt the data that is send by server
                data = DSP().convert_to_class(
                    OBJECT=recv_data,
                    secure=True,
                    secure_dict=self.get_node(
                        file=self.__file_location,
                        # key="private_key"
                        key = hashlib.sha256(bytes("private_key","utf-8")).digest()
                    )
                )
                if True:
                    # if DSP_enable option is set to True, then after this block of code will execute.
                    if True:
                        
                        # request for the secure handshake from other client
                        if data.DSP_type == "DSP_handshake_request":
                            # try:
                            if True:

                                #getd = {sender_name : "abc", target_mane : "abc", public_key : "rsa_public_key"}
                                getd = pickle.loads(base64.b64decode(eval(data.msg)))
                                aes_key = AESGCM.generate_key(256)
                                nonce = os.urandom(32)
                                aad = bytes(self.name_generator(),"utf-8")
                                qw = {
                                    "aes_key" : aes_key,
                                    "nonce" : nonce,
                                    "aad" : aad
                                }
                                pickle_qw = pickle.dumps(qw)
                                b64_aes_key_pack = base64.b64encode(pickle_qw)

                                key = load_ssh_public_key(
                                    bytes(
                                        getd["rsa_public_key"],
                                        "utf-8"
                                    ),
                                    backend=default_backend()
                                )
                                ciphertext = key.encrypt(
                                    b64_aes_key_pack,
                                    padding.OAEP(
                                        mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                        algorithm = hashes.SHA256(),
                                        label = None
                                    )
                                )
                                req_res = {
                                    "sender_name" : self.__client_name,
                                    "target_name" : getd["sender_name"],
                                    "dspReqRes" : "approved",
                                    "aes_key" : base64.b64encode(ciphertext).decode()
                                }

                                qw = self.get_node(
                                    file = self.__file_location,
                                    key = hashlib.sha256(bytes("private_key","utf-8")).digest()
                                )
                                if qw is not None:
                                    dsp_data = DSP(
                                        DSP_type = "DSP_REQ_RES",
                                        device_id = self.__client_name
                                    ).messanger(
                                        MSG = base64.b64encode(pickle.dumps(req_res)),
                                        secure = True,
                                        secure_dict= qw
                                    )

                                    self.__SENDER_QUEUE.append(dsp_data)

                                    read_data = self.get_node(
                                        file = self.__file_location,
                                        key = "key",
                                        wait = False
                                    )

                                    if read_data is not None:
                                        read_data.append({getd["sender_name"] : b64_aes_key_pack})
                                        self.add_node(
                                            file = self.__file_location,
                                            node = ["key",read_data]
                                        )
                                    
                                    else:
                                        self.add_node(
                                            file = self.__file_location,
                                            node = [
                                                "key",
                                                [
                                                    {
                                                        getd["sender_name"]:
                                                        b64_aes_key_pack
                                                    }
                                                ]
                                            ]
                                        )
                                    print("Done")
                            else:
                                raise ValueError

                            # except ValueError:
                            #     print("secure attribute of client class is set to false, please set it to True if you want to use DSP")
                            #     sys.exit()

                            # except:
                            #     pass

                        # response from the client to whom you send the handshake request
                        elif data.DSP_type == "DSP_handshake_request_res":

                            if True:
                                #getd = {sender_name : "abc", target_mane : "abc", dspreqres : "approved/denied", aes_key : b'xyz'}
                                getd = pickle.loads(base64.b64decode(eval(data.msg)))
                                if getd["dspReqRes"] == "approved":

                                    key_store = self.get_node(
                                    file = self.__file_location,
                                    key = "key"
                                    )
                                    pem_rsa_private_key = ""
                                    for i,dicts in enumerate(key_store):
                                        if list(dicts.keys())[0] == getd["sender_name"]:
                                            pem_rsa_private_key = key_store[i][getd["sender_name"]]
                                            break

                                    if pem_rsa_private_key is not None:

                                        loaded_private_key = serialization.load_pem_private_key(
                                            data = pem_rsa_private_key,
                                            password = b'aw56hfseyinhy7fce4ser',
                                            backend = default_backend()
                                        )

                                        AES_KEY = loaded_private_key.decrypt(
                                            ciphertext = base64.b64decode(bytes(getd['aes_key'],"utf-8")),
                                            padding = padding.OAEP(
                                                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(),
                                                label = None
                                            )
                                        )
                                        read_data = self.get_node(
                                            file = self.__file_location,
                                            key = "key",
                                            wait = False
                                        )
                                        w = None
                                            
                                        if read_data is not None:
                                            for d in read_data:
                                                try:
                                                    if d[getd["sender_name"]]:
                                                       d[getd["sender_name"]] = AES_KEY
                                                       w = d
                                                       break 
                                                except KeyError:
                                                    print("Key not found")
                                            self.add_node(
                                                file = self.__file_location,
                                                node = ["key",[w]]
                                            )
                                        
                                        else:
                                            self.add_node(
                                                file = self.__file_location,
                                                node = [
                                                    "key",
                                                    [
                                                        {
                                                            getd["sender_name"]:
                                                            AES_KEY
                                                        }
                                                    ]
                                                ]
                                            )
                                        self.HS_Devices.append(getd["sender_name"])
                                        print(f"Handshake Approved : {getd['sender_name']}")

                        # if you have done the handshake then you are able to receive msg from that clients
                        elif data.DSP_type == "DSP_MSG":
                            #getd = {sender_name : "abc", target_mane : "abc", data : xyz}
                            getd = getd = pickle.loads(base64.b64decode(eval(data.msg)))
                            aes_key_pack = None
                            key_store = self.get_node(
                                file = self.__file_location,
                                key = "key",
                                wait = False
                            )
                            if key_store is not None:
                                for key in key_store:
                                    if list(key.keys())[0] == getd["sender_name"]:
                                        aes_key_pack = list(key.values())[0]

                            if aes_key_pack is not None:
                                aes_key_pack = pickle.loads(base64.b64decode(aes_key_pack))
                                aes_gcm = AESGCM(aes_key_pack["aes_key"])
                                decrypted_data = aes_gcm.encrypt(
                                    nonce = aes_key_pack["nonce"],
                                    data = getd["data"],
                                    associated_data=aes_key_pack["aad"]
                                )
                                getd["data"] = pickle.loads(base64.b64decode(decrypted_data))
                                getd["channel"] = data.DSP_type
                                self.__MESSAGE_HANDLER.append(
                                    getd
                                )
                                continue
                        
                    else:
                        if self.__debug:
                            print("DSP is not enabled")

                        
                    # server has send some msg
                    if data.DSP_type == "SERVER_MSG":
                        #getd = {sender_name : "abc", target_mane : "abc", data : xyz}
                            getd = getd = pickle.loads(base64.b64decode(eval(data.msg)))
                            print(f"getd : {getd}")
                            getd["channel"] = data.DSP_type
                            self.__MESSAGE_HANDLER.append(
                                getd
                            )

                    # if you have created the custom channel to listen, then this is the place where all the msg is received.
                    elif data.DSP_type in self.__CUSTOM_CHANNEL:
                        #getd = {sender_name : "abc", target_mane : "abc", data : xyz}
                            getd = getd = pickle.loads(base64.b64decode(eval(data.msg)))
                            custom_dict = {"sender_name" : "server", "channel" : data.DSP_type, "data" : getd}
                            self.__MESSAGE_HANDLER.append(
                                custom_dict
                            )
                else:
                    print("NONE")
            # except:
            #     pass

    def isRegistered(self, target : str = None) -> bool:
        if not target:
            return self.__VARIFIED
        else:
            if type(target) is type("<<T"):
                return target in list(self.HS_Devices())

    def CREATE_CHANNEL(self,channel_name : str = None, multiple : bool = None):
        """
        CREATE_CHANNEL is used to create custom channels on which user can send and receive data.
        If user wants to create a single channel then we just need to give channel name.
        If user wants to create multiple channel at a time then should give a list of channel to 'channel_name' argument and set 'multiple' to True.
        args:
            channel_name : str/list = None,
            multiple : bool = None
        Exceptions:
            TypeError : If user gives 'str' instead of 'list' to 'channel_name' and set the 'multiple' to True.

        return type:
            None
        """
        if multiple:
            if type(channel_name) == type([]):
                for channel in channel_name:
                    if channel not in self.__CUSTOM_CHANNEL:
                        self.__CUSTOM_CHANNEL.append(channel)
            else:
                raise TypeError("When 'mutliple' is to True then channel_name should be a list of multiple channel names")
        else:
            if channel_name not in self.__CUSTOM_CHANNEL:
                self.__CUSTOM_CHANNEL.append(channel_name)

    def LISTEN(self,channel : str  = None,function : object = None, ex_counter = None, args = None):

        if channel is not None:
            found = False
            index = None

            if channel in self.__CUSTOM_CHANNEL:
                for i,d in enumerate(self.__MESSAGE_HANDLER):
                    if d["channel"] == channel:
                        found = True
                        index = i
                        break
                if found:
                    if args is None:
                        p_data = self.__MESSAGE_HANDLER.pop(index)
                        self.EX_COUNTER[function.__name__] = ex_counter
                        self.__CALLBACK_LOOP.append([function,[p_data]])
                    else:
                        p_data = self.__MESSAGE_HANDLER.pop(index)
                        args = list(args)
                        args.insert(0,p_data)
                        self.EX_COUNTER[function.__name__] = ex_counter
                        self.__CALLBACK_LOOP.append([function,args])                        
        else:
            raise TypeError("'channel' should not be None")

    def __callback_loop(self,__callback_loop):
        # print("Callback Event Loop Started...")
        while True:
            for index,func in enumerate(__callback_loop):
                __callback_loop.pop(index)
                if self.EX_COUNTER[func[0].__name__] is None:
                    func[0](*func[1])
                elif self.EX_COUNTER[func[0].__name__] > 0:
                    self.EX_COUNTER[func[0].__name__] = self.EX_COUNTER[func[0].__name__] -1
                    func[0](*func[1])
                else:
                    pass
                
    def HANDSHAKE(self, target_name: str = None,notify: bool = False,wait = False):
        print("Doing Handshake...")
        try:
            if not self.__client_init:
                raise clientError

            if self.__DSP_enable == False:
                raise DSP_NOT_ENABLED

            # target_name = hashlib.sha256(target_name).digest()
            hs_lst = []
            check = self.get_node(
                file = self.__file_location,
                key = "key",
                wait = False
            )
            if check is not None:
                for d in check:
                    hs_lst.append(list(d.keys())[0])

            else:
                hs_lst = []
            
            if target_name not in hs_lst:


                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                str_public_key = public_key.public_bytes(
                    serialization.Encoding.OpenSSH,
                    serialization.PublicFormat.OpenSSH
                ).decode()

                req_dict = {
                    "sender_name": self.__client_name,
                    "target_name": target_name,
                    "rsa_public_key": str_public_key
                }

                qw = self.get_node(
                    file = self.__file_location,
                    key = hashlib.sha256(bytes("private_key","utf-8")).digest()
                )
                if qw is not None:
                    qw_b = base64.b64decode(qw)
                    p_qw_b = pickle.loads(qw_b)
                    dsp_data = DSP(
                        DSP_type = "DSP_REQ",
                        device_id=self.__client_name
                    ).messanger(
                        MSG = base64.b64encode(pickle.dumps(req_dict)),
                        secure= True,
                        secure_dict=qw
                    )
                    self.__SENDER_QUEUE.append(dsp_data)

                    read_node = self.get_node(
                        file = self.__file_location,
                        key = "key",
                        wait = False
                    )

                    if read_node is not None:
                        read_node.append(
                            {
                                target_name:
                                private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.BestAvailableEncryption(
                                    b'aw56hfseyinhy7fce4ser')
                                )
                            }
                        )
                        self.add_node(
                            file = self.__file_location,
                            node = ["key",[read_node]]
                        )
                    else:

                        self.add_node(
                            file=self.__file_location,
                            node=[
                                "key",
                                [
                                    {
                                        target_name:
                                        private_key.private_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.BestAvailableEncryption(
                                            b'aw56hfseyinhy7fce4ser')
                                        )
                                    }
                                ]
                            ]
                        )
                    print("Handshake Process Done.")
            else:
                print("Device Already Registered!")
                # self.HS_Devices = hs_lst

        except DSP_NOT_ENABLED:
            print(f"DSP_NOT_ENABLED Error:")
            print(
                "\tDSP_enable option is set to False while initializing async_client().async_client class.")
            print(
                "\tThis option is also enable by Enabler method | Enabler(DSP_enable = True")
            sys.exit()

        except clientError:
            sys.exit()

    def __sender_thread(self, sock, message_queue):
        while True:
            for i,s in enumerate(message_queue):
                sock.send(base64.b64encode(pickle.dumps([len(s)+32])))
                qwerty = sock.send(s.decode().zfill(len(s)+32).encode("utf-8"))
                message_queue.pop(i)
                
    def SEND(self,channel : str = None, data = None):

        lst = [ [1,2], {"a":1}, (1,2), {1,2,}, "a", 12, 0.45 ]
        allowed_lst= []
        for l in lst:
            allowed_lst.append(type(l))
        if type(data) in allowed_lst:
            while True:
                if self.__VARIFIED:
                    if channel in self.__CUSTOM_CHANNEL:
                        qw = self.get_node(
                            file = self.__file_location,
                            key = hashlib.sha256(bytes("private_key","utf-8")).digest()
                        )
                        if qw is not None:
                            pre_data = {
                                "client_name" : self.__client_name,
                                "channel" : channel,
                                "data" : data
                            }
                            dsp_data = DSP(
                                DSP_type = channel,
                                device_id = self.__client_name
                            ).messanger(
                                MSG = base64.b64encode(pickle.dumps(pre_data)),
                                secure = True,
                                secure_dict = qw
                            )

                            self.__SENDER_QUEUE.append(dsp_data)
                            break
        else:
            raise TypeError(f"unallowed / untransmitable type of argument 'data', {type(data)}")

    def SEND_TO_CLIENT(self,target_name : str = None,data = None):
        lst = [ [1,2], {"a":1}, (1,2), {1,2,}, "a", 12, 0.45 ]
        allowed_lst= []
        for l in lst:
            allowed_lst.append(type(l))
        if type(data) in allowed_lst:
            if self.__VARIFIED:

                hs_lst = []
                client_aes_key_pack = None

                check = self.get_node(
                    file = self.__file_location,
                    key = "key",
                    wait = False
                )
                for d in check:
                    hs_lst.append(list(d.keys())[0])
                    if list(d.keys())[0] == target_name:
                        client_aes_key_pack = list(d.values())[0]
                if target_name in hs_lst:

                    # target_name = hashlib.sha256(str(target_name)).digest()
                    qw = self.get_node(
                        file = self.__file_location,
                        key = hashlib.sha256(bytes("private_key","utf-8")).digest()
                    )

                    if qw is not None:
                        client_aes_key_pack = base64.b64decode(client_aes_key_pack)
                        client_aes_key_pack = pickle.loads(client_aes_key_pack)

                        aes_gcm = AESGCM(client_aes_key_pack["aes_key"])
                        encrypted_data = aes_gcm.encrypt(
                            nonce = client_aes_key_pack["nonce"],
                            data = base64.b64encode(pickle.dumps(data)),
                            associated_data = client_aes_key_pack["aad"]
                        )

                        asa = {
                            "sender_name" : self.__client_name,
                            "target_name" : target_name,
                            "data" : encrypted_data
                        }

                        dsp_data = DSP(
                            DSP_type = "DSP_MSG",
                            device_id = self.__client_name
                        ).messanger(
                            MSG = base64.b64encode(pickle.dumps(asa)),
                            secure = True,
                            secure_dict = qw
                        )

                        self.__SENDER_QUEUE.append(dsp_data)
        else:
            raise TypeError(f"unallowed / untransmitable type of argument 'data', {type(data)}")

class client():

    def __init__(self,client_name: str = None, DSP_enable: bool = True, file=None, debug: bool = False, rememberServer=True):

        __parent = MAIN(
            client_name = client_name,
            DSP_enable = DSP_enable,
            file = file,
            debug = debug,
            rememberServer = rememberServer
            )

        self.CLIENT = __parent.CLIENT
        self.HS_Devices = __parent.HS_Devices
        self.isRegistered = __parent.isRegistered
        self.CREATE_CHANNEL = __parent.CREATE_CHANNEL
        self.LISTEN = __parent.LISTEN
        self.HANDSHAKE = __parent.HANDSHAKE
        self.SEND = __parent.SEND
        self.SEND_TO_CLIENT = __parent.SEND_TO_CLIENT