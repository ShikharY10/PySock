import select
import socket
import base64
import pickle
import threading
import multiprocessing

class MAIN():

    def __init__(self,secure = False, DSP_enable=False, file = None, debug = False, MTCL : bool = True, MPCL : bool = None):

        self.__debug = debug

        if MPCL and MTCL:
            raise ValueError("both 'MPCL' abd 'MTCL' should not be set to True")

        elif not MPCL and not MTCL:
            raise ValueError("both 'MPCL' abd 'MTCL' should not be set to False")

        else:
            self.__MPCL = MPCL
            self.__MTCL = MTCL

        if secure:
            if not file:
                raise TypeError("__init__() missing 1 required positional argument: 'file'")
            else:
                self.__secure = secure
                self.__file_location = file

        else:
            self.__secure = secure

        self.__READABLE = []
        self.__WRITABLE = []
        self.__INPUTS = []
        self.__OUTPUTS = []
        self.__MESSAGE_QUEUES = {}
        self.__CUSTOM_CHANNEL = []
        self.__CALLBACK_LOOP = []
        self.__RECEIVING_MSG = []
        self.__MESSAGE_HANDLER = []
        self.__BYPASS_MSG  = []
        self.__SENDER_QUEUE = []
        self.conClients = []
        
    def SERVER(self, address : str = None, port : int = None, listeners : int = None):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)

        self.sock.bind((address, port))
        self.sock.listen(listeners)

        if self.__debug:
            print("[SERVER IS ACTIVATED | LISTENING]")

        self.__INPUTS.append(self.sock)

        server_thread = threading.Thread(
            target = self.__server,
            args = ()
        )

        receiver_thread = threading.Thread(
            target=self.__handler,
            args = (
                self.__RECEIVING_MSG,
                self.__BYPASS_MSG,
                self.__CUSTOM_CHANNEL,
                self.__MESSAGE_HANDLER
            )
        )

        sender_thread = threading.Thread(
            target=self.__sender,
            args = (
                self.__WRITABLE,
                self.__MESSAGE_QUEUES,
                self.__BYPASS_MSG,
                self.__SENDER_QUEUE,
            )
            )

        if self.__MTCL:
            callback_loop_thread = threading.Thread(
                target=self.__callback_loop,
                args = (
                    self.__CALLBACK_LOOP,
                )
            )
        if self.__MTCL:
            callback_loop_process = multiprocessing.Process(
                target=self.__callback_loop,
                args = (
                    self.__CALLBACK_LOOP,
                )
            )

        server_thread.daemon = True
        receiver_thread.daemon = True
        sender_thread.daemon = True

        server_thread.start()
        receiver_thread.start()
        sender_thread.start()
        if self.__MTCL:
            callback_loop_thread.daemon = True
            callback_loop_thread.start()
        else:
            callback_loop_thread.daemon = True
            callback_loop_process.start()

    def __server(self):
        data_recv_len = []

        while True:
            readable, writable, exception = select.select(self.__INPUTS, self.__OUTPUTS, self.__INPUTS)

            for r in readable:

                if r is self.sock:
                    con,addr = r.accept()
                    con.setblocking(False)
                    self.__INPUTS.append(con)
                    self.__MESSAGE_QUEUES[con] = "no_data"

                else:
                    ini = list(zip(*data_recv_len))
                    if len(ini) == 0 or r not in ini[0]:
                        try:
                            data_len = int(r.recv(32).decode().strip("-"))
                        except ConnectionResetError:
                            print("User Disconnected")
                            if r in self.__OUTPUTS:
                                self.__OUTPUTS.remove(r)
                            if r in self.__WRITABLE:
                                self.__WRITABLE.remove(r)
                            self.__INPUTS.remove(r)
                            r.close()
                            del self.__MESSAGE_QUEUES[r]
                            continue
                        except:
                            pass

                        if data_len:
                            data_recv_len.append([r,data_len])
                        else:
                            print("User Disconnected")
                            if r in self.__OUTPUTS:
                                self.__OUTPUTS.remove(r)
                            self.__INPUTS.remove(r)
                            if r in self.__WRITABLE:
                                self.__WRITABLE.remove(r)
                            r.close()
                            del self.__MESSAGE_QUEUES[r]
                            continue
                    else:
                        INDEX = ini[0].index(r)
                        try:
                            recv_len = data_recv_len.pop(INDEX)[1]
                            data = r.recv(recv_len)
                            data = pickle.loads(base64.b64decode(data))
                            if self.__MESSAGE_QUEUES[r] == "no_data":
                                self.__MESSAGE_QUEUES[r] = data.strip("0")
                                self.conClients.append(data.strip("0"))
                                if r not in self.__OUTPUTS:
                                    self.__OUTPUTS.append(r)
                            else:
                                self.__RECEIVING_MSG.append(data)
                                if r not in self.__OUTPUTS:
                                    self.__OUTPUTS.append(r)
                            
                        except ConnectionResetError:
                            print("User Disconnected")
                            if r in self.__OUTPUTS:
                                self.__OUTPUTS.remove(r)
                            self.__INPUTS.remove(r)
                            if r in self.__WRITABLE:
                                self.__WRITABLE.remove(r)
                            r.close()
                            del self.__MESSAGE_QUEUES[r]
                            continue
                        except EOFError:
                            pass
            for w in writable:
                if w not in self.__WRITABLE:
                    self.__WRITABLE.append(w)

            for e in exception:
                self.__INPUTS.remove(e)
                if e in self.__OUTPUTS:
                    self.__OUTPUTS.remove(e)
                e.close()
                del self.__MESSAGE_QUEUES[e]

    def __handler(self,__receivingMsg, __bypassMsg,__customChannel,__messageHandler):
        while True:
            for i, _data_ in enumerate(__receivingMsg):
                if _data_["channel"] == "DSP_MSG":
                    __bypassMsg.append([_data_["target_name"],_data_])
                    __receivingMsg.pop(i)
                elif _data_["channel"] in __customChannel:
                    __messageHandler.append(_data_)
                    __receivingMsg.pop(i)

    def __sender(self,__writable, __messageQueue, __bypassMsg, __senderQueue ):
        while True:

            for s in __writable:
                if s._closed and s.fileno() == -1:
                    __writable.remove(s)
                try:
                    username = self.__MESSAGE_QUEUES[s]
                except KeyError:
                    pass
                bypassMsg = list(zip(*__bypassMsg))
                sender_q = list(zip(*__senderQueue))

                if len(bypassMsg) > 0:
                    if username in bypassMsg[0]:
                        INDEX = bypassMsg[0].index(username)
                        prepare_send = base64.b64encode(pickle.dumps(bypassMsg[1][INDEX]))
                        s.send(str(len(prepare_send)).center(16,"|").encode("utf-8"))
                        s.send(prepare_send)
                        __bypassMsg.pop(INDEX)
                        print("Message bypasses")

                if len(sender_q) > 0:
                    if username in sender_q[0]:
                        INDEX = sender_q[0].index(username)
                        prepare_send = base64.b64encode(pickle.dumps(sender_q[1][INDEX]))
                        s.send(str(len(prepare_send)).center(16,"|").encode("utf-8"))
                        s.send(prepare_send)
                        __senderQueue.pop(INDEX)


    def __callback_loop(self,__callbackLst):
        while True:
            for i,func in enumerate(__callbackLst):
                __callbackLst.pop(i)
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

    def SEND(self,target_name, channel : str = None, data = None):
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
                prepare_send = {
                    "channel" : channel,
                    "sender_name" : "SERVER",
                    "target_name" : target_name,
                    "data" : data
                }
                self.__SENDER_QUEUE.append([prepare_send["target_name"],prepare_send])

        else:
            raise TypeError(f"{type(data)} is not allowed as a sendable data type for 'data'")

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
                        self.__CALLBACK_LOOP.append([function,[args]])


class server():
    def __init__(self,secure = False, DSP_enable=False, file = None, debug = False, MTCL : bool = True, MPCL : bool = None):
        __parent = MAIN(secure,DSP_enable,file,debug,MTCL,MPCL)
        self.SERVER = __parent.SERVER
        self.CREATE_CHANNEL = __parent.CREATE_CHANNEL
        self.LISTEN = __parent.LISTEN
        self.SEND = __parent.SEND
        self.conClients = __parent.conClients
