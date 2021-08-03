><h3 style = "color : #7264a3">Intro</h3>

  A Python package for creating E2E ( Server to Client )encrypted TCP server-client programe, It also allows users to create a TCP chat application with E2E ( Client to Client ) encryption.

> <h3 style = "color : #7264a3">What are the features it provides</h3>

The main feature it provides is the multi client server. The server can handle 1000s of concerrent connections and send and receive data from them. In addition to this is make the connection E2E encrypted. Morever it also provide the functionality to chat with other clients ( Client to Client ) with E2E encryption.

---

><h3 style = "color : #7264a3">Sample Server</h3>

Before creating server make sure you have a .yaml file as it is required

server.py

```python
#imports
from PySocket import server

# sample function 
def abc(data):
    print(f"data : {data}")

# initializing asyncServer class
s = server(secure = True, file = r'server.yaml')

# creating server
s.SERVER(
    address = "localhost",
    port = 8080,
    listeners = 10
)

# creating channel for sending and receiving data
s.CREATE_CHANNEL("simple")

while True:
    # listening to upcoming data
    s.LISTEN(
        channel = "simple",
        function = abc,
    )

```

><h3 style = "color : #7264a3">Sample Client</h3>

Before creating server make sure you have a .yaml file as it is required

```python
#imports
from PySocket import client

#sample function
def abc(data):
    print(data)

# initializing asyncClient class
c = client("shikhar",DSP_enable=True,file = r'secure.yaml', debug=True)

#creating client
c.CLIENT("localhost",8080)

# creating channel for sending and receiving data
c.CREATE_CHANNEL(["simple","qwerty"],multiple=True)

# sending data to server
c.SEND(
    channel= "simple",
    data = "Hello, World! - from shikhar"
)

```

Thank you!

---