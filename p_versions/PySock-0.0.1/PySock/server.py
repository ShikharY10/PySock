from re import S
import select
import socket
import queue
import threading
import sys
import pickle
import time
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import yaml
import random

class IPNC():

    def __init__(self):
        pass

    def _read_yml(self,file = None):

        with open(file) as file:
            documents = yaml.full_load(file)
            return documents

    def _write_yml(self,file = None, dict_data = None,mode = "a+"):

        with open(file, mode) as file:
            yaml.dump(dict_data, file)

    def _add_node(self,file = None, node = None):
        try:
            read = self._read_yml(file)
            if read != None:
                read[node[0]]
                self._change_node_value(file,node)
            else:
                raise KeyError
        except KeyError:
            node_dict = {
                node[0] : node[1]
            }
            self._write_yml(file, node_dict)

    def _change_node_value(self,file = None, node = None):
        r_yml = self._read_yml(file)
        r_yml[node[0]] = node[1]
        self._write_yml(file = file, dict_data = r_yml, mode = "w")

    def _get_node(self,file = None, key = None, wait = True):
        # print(key)
        if key == None:
            return self._read_yml(file)
        
        if wait:
            while True:
                r_yml = self._read_yml(file)
                try:
                    value = r_yml[key]
                    return value
                except KeyError:
                    # print("key not found")
                    pass

                except TypeError:
                    pass
        else:
            r_yml = self._read_yml(file)
            try:
                value = r_yml[key]
                return value
            except KeyError:
                # print("key not found")
                return None

            except TypeError:
                pass

    def _remove_node(self,file,node):
        try:
            r_yml = self._read_yml(file = file)
            r_yml[node]
            r_yml.pop(node)
            self._write_yml(file = file, dict_data = r_yml, mode = "w")
            
        except KeyError:
            print("key not found")
            #pass
        except:
            pass
    def _name_generator(self,_len_ = 16, onlyText = False):
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




# creating header/wrapper class for tcp connection
class DSP():
    
    def __init__(
        self,
        msg : str = None,
        DSP_type : str = None,
        device_id : int = None,
        universalAesKey : bytes = None,
        nonce : bytes  = None,
        aad : str = None,
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
        
    def _messanger(self,MSG = None):
        if MSG is not None:
            self.msg = MSG
        data = f'DSP("{self.msg}","{self.DSP_type}")'
        # print(f"data line 61 : {data}")
        data = pickle.dumps(data)
        pickled_data = data
        encrypted_data = [self.device_id, self.__encrypt(pickled_data)]
        p_e_d = pickle.dumps(encrypted_data)
        ret = base64.b64encode(p_e_d)
        return ret
    
    def __repr__(self):
        return "_main.DSP._"
    
    def __encrypt(self,data):
        aesgcm = AESGCM(self.UNIVERSAL_AES_KEY,)
        ct = aesgcm.encrypt(
            self.NONCE,
            data,
            self.AAD
        )
        return ct
    
    def _convert_to_class(self,OBJECT : bytes = None,secure : bool = True, secure_dict : list = None):
        # try:
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

class __asyncServer(IPNC):

    def __init__(self,secure : bool = True,file = None):

        """async_server initializer class that will create the a asyncronouse tcp server.
        """
        IPNC.__init__(self)

        self.__secure = secure
        self.__file_location = file

        self.READABLE = []
        self.WRITABLE = []
        self.INPUTS = []
        self.OUTPUTS = []
        self.MESSAGE_QUEUES = {}
        self.REQUEST_LIST = []
        self.REQUEST_RESPONSE_LIST = []
        self.MESSAGE_LIST = []

        self.__VARIFIED_DEVICES = []
        self.__CLIENT_KEYS = {}
        self.__CUSTOM_CHANNEL = []
        self.__CUSTOM_CHANNEL_MSG_REC = []
        self.__CUSTOM_CHANNEL_MSG_SEND = []
        self.__VARIFIER_LIST = []
        self.__CALLBACK_LOOP = []
        self.__RECEIVING_MSG = []

        
        get = self._get_node(file = self.__file_location,key = hashlib.sha256(bytes("key", "utf-8")).digest(), wait = False)
        if get is not None:
            self.__CLIENT_KEYS = get
            # print(self.__CLIENT_KEYS)
            self.__VARIFIED_DEVICES.extend(list(get.keys()))

    def SERVER(self,address : str = None, port : int = None, listeners : int = None):

        self.address = address
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        self.sock.setblocking(0)

        self.sock.bind((self.address,self.port))
        self.sock.listen(listeners)
        print("[SERVER IS ACTIVATED | LISTENING]")
        self.INPUTS.append(self.sock)

        thread1 = threading.Thread(
            target = self.receive_func,
            args = (
                self.__RECEIVING_MSG,
                self.__VARIFIED_DEVICES,
                self.__VARIFIER_LIST,
                self.__CLIENT_KEYS,
                self.OUTPUTS,
                self.REQUEST_LIST,
                self.REQUEST_RESPONSE_LIST,
                self.MESSAGE_LIST,
                self.__CUSTOM_CHANNEL_MSG_REC,
            )
        )

        thread2 = threading.Thread(
            target = self.send_func,
            args = (
                self.WRITABLE,
                self.MESSAGE_QUEUES,
                self.MESSAGE_LIST,
                self.REQUEST_LIST,
                self.REQUEST_RESPONSE_LIST,
                self.__VARIFIER_LIST,
                self.__CUSTOM_CHANNEL_MSG_SEND
            )
        )

        thread3 = threading.Thread(
            target = self.__callback_loop,
            args = (
                self.__CALLBACK_LOOP,
            )
        )

        # thread1.daemon = True
        thread1.start()

        # thread2.daemon = True
        thread2.start()

        # thread3.daemon = True
        thread3.start()

        thread = threading.Thread(target = self.__server)
        # thread.daemon = True
        thread.start()

    def __server(self):
        data_recv_len = []
        
        while True:
            readable, writable, exceptions = select.select(self.INPUTS, self.OUTPUTS, self.INPUTS)

            # handling the inputs
            for r in readable:
                if r is self.sock:
                    # print("Parent Sock...")
                    connection,addr = r.accept()
                    connection.setblocking(0)
                    self.INPUTS.append(connection)
                    self.MESSAGE_QUEUES[connection] = queue.Queue()
                else:
                    ini = list(zip(*data_recv_len))
                    if len(ini) == 0 or r not in ini[0]:
                        try:
                            data_len = pickle.loads(base64.b64decode(r.recv(32).decode().strip("0").encode("utf-8")))
                        except ConnectionResetError:
                            print("Client Disconnected")
                            if r in self.OUTPUTS:
                                self.OUTPUTS.remove(r)
                            if r in self.WRITABLE:
                                self.WRITABLE.remove(r)
                            self.INPUTS.remove(r)
                            r.close()
                            del self.MESSAGE_QUEUES[r]
                            continue

                        except Exception as e:
                            pass
                        if data_len:
                            if type(data_len) == type([]):
                                data_recv_len.append(
                                    [
                                        r,
                                        data_len[0]
                                    ]
                                )
                        else:
                            print("User Disconnected")
                            if r in self.OUTPUTS:
                                self.OUTPUTS.remove(r)
                            self.INPUTS.remove(r)
                            if r in self.WRITABLE:
                                self.WRITABLE.remove(r)
                            r.close()
                            del self.MESSAGE_QUEUES[r]
                            continue
                    else:
                        qwe = list(zip(*data_recv_len))
                        INDEX = qwe[0].index(r)
                        
                        try:
                            recv_len = data_recv_len.pop(INDEX)[1]
                            data = r.recv(recv_len)
                            try:
                                data = data.decode().strip("0").encode("utf-8")
                            except:
                                print("Error in decoding")
                            self.__RECEIVING_MSG.append(data)
                            self.MESSAGE_QUEUES[r].put(pickle.loads(base64.b64decode(data))[0])
                            
                            if r not in self.OUTPUTS:
                                self.OUTPUTS.append(r)

                        except Exception as e:
                            print("User Disconnected")
                            readable.remove(r)
                            self.INPUTS.remove(r)
                            writable.remove(r)
                            self.OUTPUTS.remove(r)
                            if r in self.WRITABLE:
                                self.WRITABLE.remove(r)
                            del self.MESSAGE_QUEUES[r]
                            continue
                  
            # handling the outputs
            for w in writable:
                if w not in self.WRITABLE:
                    self.WRITABLE.append(w)

            # handling the errors
            for e in exceptions:
                self.INPUTS.remove(e)
                if e in self.OUTPUTS:
                    self.OUTPUTS.remove(e)
                e.close()
                del self.MESSAGE_QUEUES[e]

    # @jit(nopython  = True)
    def receive_func(self, __receiving_msg,__varified_devices, __varifier_lst, __client_keys, __outputs, __request_lst, __request_res_lst, __message_lst, __custom_c_m_r):

        # __receiving_msg  = self.__RECEIVING_MSG,
        # __varified_devices = self.__VARIFIED_DEVICES,
        # __varifier_lst = self.__VARIFIER_LIST,
        # __client_keys = self.__CLIENT_KEYS,
        # __outputs = self.OUTPUTS,
        # __request_lst = self.REQUEST_LIST
        # __request_res_lst = self.REQUEST_RESPONSE_LIST
        # __message_lst = self.MESSAGE_LIS
        # __custom_c_m_r = self.__CUSTOM_CHANNEL_MSG_REC
        
        while True:
            # print(__client_keys)
            try:
                for INDEX,_data_ in enumerate(__receiving_msg):
                    data = pickle.loads(base64.b64decode(_data_))
                    if data[0] not in __varified_devices:
                        _recv_ = DSP()._convert_to_class(_data_, secure = False)
                        if _recv_.DSP_type == "username_secure":
                            resolved_data = eval(_recv_.msg)
                            aes_key = AESGCM.generate_key(256)
                            nonce = os.urandom(32)
                            aad = bytes(self._name_generator(),"utf-8")
                            qw = {
                                "aes_key" : aes_key,
                                "nonce" : nonce,
                                "aad" : aad,
                            }

                            pickle_qw = pickle.dumps(qw)
                            b64_aes_key_pack = base64.b64encode(pickle_qw)
                            key = load_ssh_public_key(
                                bytes(
                                    resolved_data["data"],
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
                            ciphertext = base64.b64encode(ciphertext)
                            prepare_data = {"key" : ciphertext}
                            
                            dsp_data = DSP(
                                DSP_type="username_secure_response"
                            )._messanger(
                                MSG = prepare_data
                            )
                            dsp_data = [resolved_data["username"],dsp_data]
                            __varifier_lst.append(dsp_data)

                            __varified_devices.append(resolved_data["username"])
                            __client_keys[resolved_data["username"]] = b64_aes_key_pack

                            get = self._get_node(
                                file = self.__file_location,
                                key = hashlib.sha256(bytes("key","utf-8")).digest(),
                                wait = False
                            )
                            if get is not None:
                                get[resolved_data["username"]] = b64_aes_key_pack
                                self._add_node(
                                    file = self.__file_location,
                                    node = [
                                        hashlib.sha256(bytes("key","utf-8")).digest(),
                                        get
                                    ]
                                )
                            else:
                                self._add_node(
                                    file = self.__file_location,
                                    node = [
                                        hashlib.sha256(bytes("key","utf-8")).digest(),
                                        {
                                            resolved_data["username"] : b64_aes_key_pack
                                        }
                                    ]
                                )

                            __receiving_msg.pop(INDEX)

                    else:
                        aes_key_pack = __client_keys[data[0]]

                        _recv_ = DSP()._convert_to_class(
                            OBJECT = _data_,
                            secure = True,
                            secure_dict = aes_key_pack
                        )

                        # Handling the DSP request from users.
                        if _recv_.DSP_type == "DSP_REQ":
                            try:
                                resolved_data = eval(_recv_.msg)
                                resolved_data = pickle.loads(base64.b64decode(eval(_recv_.msg)))
                                __request_lst.append(
                                    [
                                        resolved_data["target_name"],
                                        _recv_.msg
                                    ]
                                )
                                __receiving_msg.remove(_data_)

                            except:
                                pass

                        # Handling the DSP request response from users.
                        elif _recv_.DSP_type == "DSP_REQ_RES":
                            try:
                                resolved_data = pickle.loads(base64.b64decode(eval(_recv_.msg)))

                                __request_res_lst.append(
                                    [
                                        resolved_data["target_name"],
                                        _recv_.msg
                                    ]
                                )
                                __receiving_msg.remove(_data_)
                            except:
                                pass

                        elif _recv_.DSP_type == "DSP_MSG":
                            try:
                                resolved_data = pickle.loads(base64.b64decode(eval(_recv_.msg)))
                                __message_lst.append(
                                    [
                                        resolved_data['target_name'],
                                        _recv_.msg 
                                    ]
                                )
                                __receiving_msg.remove(_data_)
                            except:
                                pass

                        elif _recv_.DSP_type in self.__CUSTOM_CHANNEL:
                            try:
                                resolved_data = pickle.loads(base64.b64decode(eval(_recv_.msg)))
                                __custom_c_m_r.append(resolved_data)
                                __receiving_msg.remove(_data_)
                            except:
                                pass  

            except:
                pass

    # @jit(nopython  = True)
    def send_func(self,Writable,message_q,message_list,requestList,requestResList,varifierList,customChannelMessageSend):
        # print("send_func called...")
        while True:
            for s in Writable:
                if s._closed == True and s.fileno() == -1:
                    Writable.remove(s)
                
                # try:
                try:
                    username = message_q[s].get_nowait()
                    message_q[s].put(username)
                    msg_lst = list(list(zip(*message_list)))
                    req_lst = list(list(zip(*requestList)))
                    req_res_lst = list(list(zip(*requestResList)))
                    vari_lst = list(list(zip(*varifierList)))
                    send_c_msg = list(zip(*customChannelMessageSend))
                except KeyError:
                    pass

                # print(f"requestList : {requestList}")


                if len(msg_lst) > 0:
                    if username in msg_lst[0]:
                        INDEX = msg_lst[0].index(username)

                        aes_key_pack = self.__CLIENT_KEYS[username]
                        aes_key_pack = pickle.loads(base64.b64decode(aes_key_pack))

                        dsp_data = DSP(
                            DSP_type = "DSP_MSG",
                            universalAesKey = aes_key_pack["aes_key"],
                            nonce = aes_key_pack["nonce"],
                            aad = aes_key_pack["aad"]
                        )._messanger(
                            MSG = f"{msg_lst[1][INDEX]}"
                        ).decode().center(len(msg_lst[1][INDEX]) + 100, "|").encode("utf-8")
                        try:
                            s.send(bytes(f"{len(dsp_data)}".center(16,"|"),"utf-8"))
                            s.send(
                                dsp_data
                            )
                            message_list.pop(INDEX)
                        except OSError:
                            # print(f"msg_lst : {msg_lst}")
                            # print(f"Writable : {Writable}")
                            pass
                        
                        # print("Send...")

                if len(req_lst) > 0:
                    # print(f"req_lst : {req_lst}")
                    if username in req_lst[0]:
                        INDEX = req_lst[0].index(username)
                        try:
                            aes_key_pack = self.__CLIENT_KEYS[username]
                        except KeyError:
                            continue
                        # aes_key_pack = base64.b64decode(pickle.loads(aes_key_pack))
                        aes_key_pack = pickle.loads(base64.b64decode(aes_key_pack))
                        # print(f"req_lst[1][INDEX] : {req_lst[1][INDEX]}")
                        dsp_data = DSP(
                                DSP_type = "DSP_handshake_request",
                                universalAesKey = aes_key_pack["aes_key"],
                                nonce = aes_key_pack["nonce"],
                                aad = aes_key_pack["aad"]
                            )._messanger(
                                MSG = f"{req_lst[1][INDEX]}"
                            ).decode().center(len(req_lst[1][INDEX]) + 100, "|").encode("utf-8")

                        # print("Sending DSP Request...")
                        # print(f"target name : {username}")
                        s.send(bytes(f"{len(dsp_data)+100}".center(16,"|"),"utf-8"))
                        s.send(
                            dsp_data
                        )
                        requestList.pop(INDEX)
                
                if len(req_res_lst) > 0:
                    if username in req_res_lst[0]:
                        INDEX = req_res_lst[0].index(username)

                        aes_key_pack = self.__CLIENT_KEYS[username]
                        aes_key_pack = pickle.loads(base64.b64decode(aes_key_pack))

                        dsp_data = DSP(
                                DSP_type = "DSP_handshake_request_res",
                                universalAesKey = aes_key_pack["aes_key"],
                                nonce = aes_key_pack["nonce"],
                                aad = aes_key_pack["aad"]
                            )._messanger(
                                MSG = f"{req_res_lst[1][INDEX]}"
                            ).decode().center(len(req_res_lst[1][INDEX]) + 100, "|").encode("utf-8")

                        s.send(bytes(f"{len(dsp_data)+100}".center(16,"|"),"utf-8"))
                        s.send(
                            dsp_data
                        )
                        requestResList.pop(INDEX)

                if len(vari_lst) > 0:
                    if username in vari_lst[0]:
                        INDEX = vari_lst[0].index(username)
                        s.send(bytes(f"{len(vari_lst[1][INDEX])}".center(16,"|"),"utf-8"))
                        s.send(
                            vari_lst[1][INDEX]
                        )
                        varifierList.pop(INDEX)

                if len(send_c_msg) > 0:
                    if username in send_c_msg[0]:
                        INDEX = send_c_msg[0].index(username)
                        s.send(bytes(f"{len(send_c_msg[1][INDEX])}".center(16,"|"),"utf-8"))
                        s.send(send_c_msg[1][INDEX])
                        customChannelMessageSend.pop(INDEX)
                # except:
                #     pass

    def CREATE_CHANNEL(self,channel_name = None, multiple : bool = False):
        if multiple:
            if type(channel_name) == type([]):
                for channel in channel_name:
                    if channel not in self.__CUSTOM_CHANNEL:
                        self.__CUSTOM_CHANNEL.append(channel)
                    else:
                        print(f"Channel : {channel} already exists.")
            else:
                raise TypeError("When 'mutliple' is to True then channel_name should be a list of multiple channel names")
        else:
            if channel_name not in self.__CUSTOM_CHANNEL:
                self.__CUSTOM_CHANNEL.append(channel_name)

    def LISTEN(self,channel : str  = None,function : object = None,args = None):

        if channel is not None:
            found = False
            index = None

            if channel in self.__CUSTOM_CHANNEL:
                for i,d in enumerate(self.__CUSTOM_CHANNEL_MSG_REC):
                    if d["channel"] == channel:
                        found = True
                        index = i
                        break
                if found:
                    if args is None:
                        p_data = self.__CUSTOM_CHANNEL_MSG_REC.pop(index)
                        self.__CALLBACK_LOOP.append([function,[p_data]])
                    else:
                        p_data = self.__CUSTOM_CHANNEL_MSG_REC.pop(index)
                        args = list(args)
                        args.insert(0,p_data)
                        self.__CALLBACK_LOOP.append([function,args])
        else:
            raise TypeError("'channel' should not be None")

    def __callback_loop(self,__callback_loop):
        # print("Callback Event Loop Started...")
        while True:
            for index,func in enumerate(__callback_loop):
                __callback_loop.pop(index)
                func[0](*func[1])

    def SEND(self,channel_name,target_name,data):
        if channel_name in self.__CUSTOM_CHANNEL:
            key_pack = self.__CLIENT_KEYS[target_name]
            key_pack = base64.b64decode(pickle.loads(key_pack))
            dsp_data = DSP(
                DSP_type = channel_name,
                universalAesKey=key_pack["aes_key"],
                nonce = key_pack["nonce"],
                aad= key_pack["aad"]
            )._messanger(
                MSG = base64.b64encode(pickle.dumps(data))
            )
            self.__CUSTOM_CHANNEL_MSG_SEND.append(
                target_name,
                dsp_data
            )

class server():
    def __init__(self, secure : bool = True, file : str = None):
        """
        This class allows user to create multi-client server.
        args: 
            secure : bool = True -> this should set to the default value True,
            file : str = None -> here user need to pass a yaml file which saves all the keys and configurations.
                if not specified, will raise an TypeError
        """

        if not file:
            raise TypeError("asyncServer() missing 1 required positional argument: 'file'")

        __parent = __asyncServer(secure = secure, file = file)

        self.SERVER = __parent.SERVER
        self.CREATE_CHANNEL  = __parent.CREATE_CHANNEL
        self.LISTEN = __parent.LISTEN
        self.SEND = __parent.SEND

