import socket
import base64
import pickle
import threading
import multiprocessing
import hashlib

class MAIN():

    def __init__(self,client_name : str = None, secure = False, DSP_enable : bool = False, file : str = None, debug : bool = False, rememberServer = True, MPCL : bool = False, MTCL : bool = True):

        self.__debug = debug
        
        if secure:
            if not file:
                raise TypeError("__init__() missing 1 required positional argument: 'file'")
            else:
                self.__secure = secure
                self.__file_location = file
                self.__DSP_enable = DSP_enable
                self.__rememberSever = rememberServer
                self.__client_name = hashlib.sha256(bytes(client_name,"utf-8")).digest()
        else:
            self.__secure = secure
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
        self.__EX_COUNTER = {}

        if rememberServer:
            pass
        
        self.__CUSTOM_CHANNEL.append("DSP_MSG")

    def CLIENT(self,address : str = None, port : int = None):

        if self.__debug:
            print("[Connecting To Server]")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((address,port))
        ini = base64.b64encode(pickle.dumps(self.__client_name))
        self.sock.send(bytes(str(len(ini)).center(32,"-"),"utf-8"))
        self.sock.send(ini)
        if self.__debug:
            print("[Connected]")

        if self.__secure:
            self.__VARIFIED = self.get_node(
                file = self.__file_location,
                key = hashlib.sha256(bytes("__VARIFIED","utf-8")).digest()
            )

        receiver_thread = threading.Thread(
            target = self.__receiver,
            args = ()
            )

        sender_thread = threading.Thread(
            target = self.__sender,
            args = (
                self.sock,
                self.__SENDER_QUEUE
            )
        )

        if self.__MTCL:
            callback_loop_thread_process = threading.Thread(
                target = self.__callback_loop,
                args = (self.__CALLBACK_LOOP,)
            )
        else:
            callback_loop_thread_process = multiprocessing.Thread(
                target = self.__callback_loop,
                args = (self.__CALLBACK_LOOP,)
            )

        receiver_thread.start()
        sender_thread.start()
        callback_loop_thread_process.start()

        if self.__secure:
            if not self.__VARIFIED:
                pass

    def __receiver(self):
        if self.__secure:
            while True:
                if not self.__VARIFIED:
                    pass
                else:
                    pass
        else:
            while True:
                data_len = int(self.sock.recv(16).decode().strip("|"))

                if not data_len:
                    self.sock.close()
                    raise ConnectionError("[SERVER GOES DOWN - CONNECTION LOST]")

                recv_data = self.sock.recv(data_len).decode().strip("|").encode("utf-8")

                recv_data = pickle.loads(base64.b64decode(recv_data))
                if type(recv_data) is type({}):
                    if recv_data["channel"] == "DSP_MSG":
                        
                        self.__MESSAGE_HANDLER.append(recv_data)
                    elif recv_data["channel"] in self.__CUSTOM_CHANNEL:
                        self.__MESSAGE_HANDLER.append(recv_data)
                    
    def __sender(self,sock,message_queue):
        while True:
            for i,s in enumerate(message_queue):
                
                prepare_for_send = base64.b64encode(pickle.dumps(s))
                sock.send(bytes(str(len(prepare_for_send)).center(32,"-"),"utf-8"))
                sock.send(prepare_for_send)
                message_queue.pop(i)

    def __callback_loop(self,callback_lst):
        while True:
            for i,func in enumerate(callback_lst):
                callback_lst.pop(i)
                func[0](*func[1])

    def CREATE_CHANNEL(self,channels : str = None, multiple : bool = False):
        if multiple:
            if type(channels) is type([]):
                for channel in channels:
                    if channel not in self.__CUSTOM_CHANNEL:
                        self.__CUSTOM_CHANNEL.append(channel)
        else:
            if channels not in self.__CUSTOM_CHANNEL:
                self.__CUSTOM_CHANNEL.append(channels)
        pass

    def HANDSHAKE(self):
        pass

    def LISTEN(self,channel : str = None, function : object = None, ex_counter = None, args = None):
        if not channel:
            raise TypeError("LISTEN() missing 1 required positional argument: 'channel'")
        else:
            found = False
            index = None
            
            if channel in self.__CUSTOM_CHANNEL:
                for i,d in enumerate(self.__MESSAGE_HANDLER):
                    if d["channel"] == channel:
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
                    "channel" : channel,
                    "sender_name" : self.__client_name,
                    "target_name" : "SERVER",
                    "data" : data
                    }
                self.__SENDER_QUEUE.append(prepare_send_data)


    def SEND_TO_CLIENT(self,target_name : str = None, data = None):
        if not target_name:
            raise TypeError("SEND() missing 1 required positional argument: 'target_name'")
        if not data:
            raise TypeError("SEND() missing 1 required positional argument: 'data'")

        lst = [ [1,2], {"a":1}, (1,2), {1,2,}, "a", 12, 0.45, b"bytes" ]
        allowed_lst= []
        for l in lst:
            allowed_lst.append(type(l))
        if type(data) in allowed_lst:
            prepare_send_data = {
                "channel" : "DSP_MSG",
                "sender_name" : self.__client_name,
                "target_name" : target_name,
                "data" : data
            }
            self.__SENDER_QUEUE.append(prepare_send_data)
    


class client():
    def __init__(self,client_name : str = None, secure = False, DSP_enable : bool = False, file : str = None, debug : bool = False, rememberServer = True, MPCL : bool = False, MTCL : bool = True):
        __parent = MAIN(client_name,secure,DSP_enable,file,debug,rememberServer,MPCL,MTCL)
        self.CLIENT = __parent.CLIENT
        self.LISTEN = __parent.LISTEN
        self.CREATE_CHANNEL = __parent.CREATE_CHANNEL
        self.SEND = __parent.SEND
        self.SEND_TO_CLIENT = __parent.SEND_TO_CLIENT

