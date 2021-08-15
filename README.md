
A python  package for creating multi-client server with high level of abstarction, meaning user don't need to write 100s of lines of code. User can write a multi-client server with just 12 lines fo code, it's that simple.
In addition to this PySock also make the connections end-to-end encrypted. It also provide the functionality of creating a end-to-end encrypted connection between two or more client, meaning client can share the data with others client available.


In more simple terms PySock brings to versions of multi-client server. First one is just normal multi-client server with no encryption, user need to write there own wrapper kind fucntion to make it secure if they wants. Other version is highly secure. PySock implements E2E with the help of AES.
The encryption is not just limited to client-server communication but it also encrypts cleint-client communication.

## Below there are two examples listed, first is secure other is unsecure:

---

><h4 style = "color : #7264a3">Sample Secure Server</h4>

Before creating secure version of server make sure you have a .yaml file as it is required

server.py

```python
from PySock import Sserver

def client_msg(data):
    print(f"Message From : {data['sender_name']} => {data['data']}")

s = Sserver(
    file = r'server_yml.yaml',
    debug = False
    )
s.SERVER("localhost",1234,10)
s.CREATE_CHANNEL("test")

new_client = []

while True:
    for d in s.varifiedDevices:
        if d in s.conClients:       
            if d not in new_client:
                s.SEND(d,"test","Hello From Server")
                new_client.append(d)
        else:
            if d in new_client:
                new_client.remove(d)

    s.LISTEN("test",client_msg)
```


><h4 style = "color : #7264a3">Sample Secure Clients</h4>


Before creating server make sure you have a .yaml file as it is required

clientOne.py

```python
from PySock import Sclient

name = "shikhar"

def abc(data,con):
    print(f"Message from : {data['sender_name']} => {data['data']}")
    con.SEND("test","Hello!")

def client_msg(data):
    print(f"Message from : {data['sender_name']} => {data['data']}")

c = Sclient(client_name = name, file = r'clientOne_yml.yaml', debug = False)
c.CLIENT("localhost",1234)
c.CREATE_CHANNEL("test")

c.HANDSHAKE(target_name = "swat")
count = 0
while True:
    c.LISTEN( channel = "test", function = abc, args = (c,) )
    c.LISTEN( channel = "DSP_MSG", function = client_msg)

    if count == 0:
        if c.check("swat") in c.HS_Devices:
            c.SEND_TO_CLIENT(target_name = "swat", data = "Hello, what are you doing.")
            count += 1
```

clientTwo.py

```python
from PySock import Sclient

name = "swat"

def abc(data,con):
    print(f"Message from : {data['sender_name']} => {data['data']}")
    con.SEND("test","What are you doing!")

def client_msg(data,con):
    print(f"Message From : {data['sender_name']} => {data['data']}")
    con.SEND_TO_CLIENT(target_name = data["sender_name"], data = f"Hello From {name}")

c = Sclient(client_name = name, file = r'clientTwo_yml.yaml', debug = False)
c.CLIENT("localhost",1234)
c.CREATE_CHANNEL("test")

count = 0
while True:
    c.LISTEN( channel = "test", function = abc, args = (c,) )
    c.LISTEN( channel = "DSP_MSG", function = client_msg, args = (c,))

    if count == 0:
        if "swat" in c.HS_Devices:
            c.SEND_TO_CLIENT(target_name = "swat", data = "Hello, what are you doing.")
            count += 1
```

### ===You can add as many client like these===


### Result after running server.py, clientOne.py and clientTwo.py

![Markdown logo](resource/PySock-test.png)

---
---

## Now its time for normal multi-client server and clients:

><h4 style = "color : #7264a3">Sample Server</h4>

server.py

```python
from PySock import server

def client_msg(data):
    print(f"Message From : {data['sender_name']} => {data['data']}")

s = server(secure = False,debug = True)
s.SERVER("localhost",8888,10)
s.CREATE_CHANNEL("test")

new_client = []

while True:
    for d in s.conClients:
        if d not in new_client:
            s.SEND(d,"test","Hello From Server")
            new_client.append(d)

    s.LISTEN("test",client_msg)
```

><h4 style = "color : #7264a3">Sample Clients</h4>

clientOne.py

```python
from PySock import client

name = "shikhar"

def abc(data,con):
    print(f"Message from {data['sender_name']} : {data['data']}")
    con.SEND("test","Hello!")

c = client(client_name = name, debug = True)
c.CLIENT("localhost",8888)
c.CREATE_CHANNEL("test")

count = 0
while True:
    c.LISTEN( channel = "test", function = abc, args = (c,) )

    if count == 0:
        c.SEND_TO_CLIENT(target_name = "swat", data = "Hello, what are you doing.")
        count += 1

```

clientTwo.py

```python
from PySock import client

def abc(data,con):
    print(f"Message from {data['sender_name']} : {data['data']}")
    con.SEND("test","Hurrah! it's working.")

def client_msg(data):
    print(f"Message from : {data['sender_name']} => {data['data']}")

c = client(client_name = "swat", debug = True)
c.CLIENT("localhost",8888)
c.CREATE_CHANNEL("test")
while True:
    c.LISTEN( channel = "test", function = abc, args = (c,) )

    c.LISTEN( channel = "DSP_MSG", function = client_msg)
```
There is no docs for this library but i'm working on docs, hope it will uploaded soon.


Thanks for visiting 

---