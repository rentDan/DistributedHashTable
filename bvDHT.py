import hashlib
import math
from socket import *
import threading
import sys

""" Variables """

gap = (2**160 // 5)

#Finger Table <HashedKey, PeerAddress> (global)
fingerTable = {
    #prev, self, and next are string keys
    #Fingers are hashedKey(gaps) keys
    #Values are (hashedKey(spaceOwner), PeerAddress)
}

#Local Hashtable <Key, byteArray>
localHashTable = {}

#PeerAddresses are form "IP:Port"
#HashedKey are form str(128-bit integer)

""" Helper Functions/Protocols """

# Returns an integer index into the hash-space for a node Address
#  - addr is of the form ("ipAddress or hostname", portNumber)
#    where the first item is a string and the second is an integer
def getHashIndex(addr):
    b_addrStr = ("%s:%d" % addr).encode()
    return int.from_bytes(hashlib.sha1(b_addrStr).digest(), byteorder="big")

def getHashIndexString(key):
    b_keyStr = key.encode()
    return int.from_bytes(hashlib.sha1(b_keyStr).digest(), byteorder="big")

def getLocalIPAddress():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            msg = msg[:-1]
            break
    return msg.decode()

def recvAll(conn, dataLen):
    data = conn.recv(dataLen)

    while (len(data) < dataLen):
        Moredata = conn.recv(dataLen - len(data))
        if len(Moredata) == 0:
            break
        data += Moredata
    return data

def populateFingerTable():
    """
    Populates finger table with hashedKeys and peerAddresses
    for 4 fingers
    """
    global fingerTable

    for i in range(1, 5):
        finger = (hashedSelfAddress + i*gap) % (2**160)
        fingerAddress = locate(finger)
        tempIP, tempPort = fingerAddress.split(":")
        fingerHashedAddress = getHashIndex((tempIP, int(tempPort)))
        fingerTable[finger] = (fingerHashedAddress, fingerAddress)

def reviewFingerTable():
    """
    Cutoff all fingers (like in john wick 3)

    Regenerates fingers
    """
    global fingerTable

    #Destroy non string keys
    for finger in list(fingerTable.keys()):
        if isinstance(finger, int):
            del fingerTable[finger]

    #Regenerate fingers
    populateFingerTable()

def updatePrevOnNext(peerAddress):
    """
    Updates whoever is Next on their new Prev finger
    (used during connect and disconnect)
    """

    peerConn = socket(AF_INET, SOCK_STREAM)
    peerConn.connect((peerAddress.split(":")[0], int(peerAddress.split(":")[1])))

    #Send UPDATE_PREV message to the Next peer
    updateMsg = "UPDATE_PREV\n"
    peerConn.send(updateMsg.encode())

    #Send the peerAddress of self
    peerConn.send(selfAddress.encode())

    #receive Acknowledgement from the Next peer
    ack = getLine(peerConn)

    peerConn.close()

    return ack

def circularDiff(a, b):
    """
    Returns: the distance between two points in our DHT
    """
    max_val = 2**160 - 1

    return min((a-b) % max_val, (b-a) % max_val)

def inBetween(target, start, end):
    if start <= end:
        return start < target < end
    else:
        return target > start or target < end

def findClosestFinger(hashedKey):
    """
    Returns: the closest finger to the hashedKey
    """
    prevHashedKey = fingerTable["prev"][0]
    nextHashedKey = fingerTable["next"][0]
    if prevHashedKey == nextHashedKey == hashedSelfAddress:
        return "self"
    elif inBetween(hashedKey, hashedSelfAddress, nextHashedKey):
        return "self"
    elif inBetween(hashedKey, prevHashedKey, hashedSelfAddress):
        return "prev"
    else:
        ownerHashedKeys = []
        fingerHashedKeys = []

        ownerHashedKeys.append(nextHashedKey)
        fingerHashedKeys.append("next")
        for i in range(1, 5):
            finger = (hashedSelfAddress + i*gap) % (2**160)
            if finger in fingerTable:
                ownerHashedKeys.append(fingerTable[finger][0])
                fingerHashedKeys.append(finger)
        ownerHashedKeys.append(prevHashedKey)
        fingerHashedKeys.append("prev")

        for i in range(len(ownerHashedKeys)-1):
            if inBetween(hashedKey, ownerHashedKeys[i], ownerHashedKeys[i+1]):
                key = ownerHashedKeys[i]
                if key == prevHashedKey:
                    return "prev"
                elif key == nextHashedKey:
                    return "next"
                else:
                    return fingerHashedKeys[i]

def locate(hashedKey, startingPeer=None):
    """
    Returns: peerAddress of owner of the hashSpace that contains
    the data trying to be found
    """

    if startingPeer is None:
        #from local fingerTable, find the finger(peer) closest to the key(hashspace)
        #trying to be found
        closestFinger = findClosestFinger(hashedKey)

        if closestFinger == fingerTable["self"]:
            return selfAddress[:-1]

        #peerAddress is of the form "IP:Port"
        peerAddress = fingerTable[closestFinger][1]
    else:
        peerAddress = startingPeer

    peerIP, peerPort = peerAddress.split(":")

    #Start while loop with our closest peer
    while True:

        try:
            peerSocket = socket(AF_INET, SOCK_STREAM)
            peerSocket.connect((peerIP, int(peerPort)))
        except ConnectionRefusedError:
            reviewFingerTable()
            peerAddress = locate(hashedKey)
            peerIP, peerPort = peerAddress.split(":")
            peerSocket = socket(AF_INET, SOCK_STREAM)
            peerSocket.connect((peerIP, int(peerPort)))


        #Send LOCATE message to that peer
        locateMsg = "LOCATE\n"
        peerSocket.send(locateMsg.encode())

        #send key message to that peer
        hashedKeyMsg = str(hashedKey) + "\n"
        peerSocket.send(hashedKeyMsg.encode())

        #receive the closest finger from that peer
        newClosestAddress = getLine(peerSocket)

        peerSocket.close()

        #check if that peer is owner? if so, return it
        if newClosestAddress == peerAddress:
            return newClosestAddress

        peerAddress = newClosestAddress
        peerIP, peerPort = peerAddress.split(":")

""" Main Protocols """

def connect(peerSocket):
    global fingerTable

    peerSocket.sendall("CONNECT\n".encode())
    peerSocket.sendall((str(hashedSelfAddress) + "\n").encode())

    # check if the person owns our hashedKey space
    ack = getLine(peerSocket)
    if ack == "0":
        # break
        return 0

    # get the number of files we will receive
    numFiles = int(getLine(peerSocket))
    for _ in range(numFiles):
        hk = int(getLine(peerSocket)) #         recieve hashedkey
        size = int(getLine(peerSocket)) #       recieve len of byte array
        data = recvAll(peerSocket, size) #      recieve byte array
        localHashTable[hk] = data #             store data in local hashTable

    # add self, next, and prev to our finger table
    peerIP, peerPort = peerSocket.getpeername()
    nextPeerAddress = getLine(peerSocket)
    temp = nextPeerAddress.split(":")
    nextIP = temp[0]
    nextPort = int(temp[1])
    fingerTable["self"] = (hashedSelfAddress, selfAddress[:-1])
    fingerTable["next"] = (getHashIndex((nextIP, nextPort)), (f"{nextIP}:{nextPort}"))
    fingerTable["prev"] = (getHashIndex((peerIP, peerPort)), (f"{peerIP}:{peerPort}"))

    # send our peerAddress
    peerSocket.sendall(selfAddress.encode())
    # update prev on next
    updatePrevOnNext(nextPeerAddress)

    return 1

def disconnect(peerSocket):
    # send disconnect to our prev
    peerSocket.sendall("DISCONNECT\n".encode())
    # send our next so prev can update their nexrt
    peerSocket.sendall((fingerTable["next"][1] + "\n").encode())
    # send the size of our hashTable
    peerSocket.sendall((str(len(localHashTable)) + "\n").encode())

    # send all files
    for hk, data in localHashTable.items():
        peerSocket.sendall((str(hk) + "\n").encode())
        peerSocket.sendall((str(len(data)) + "\n").encode())
        peerSocket.sendall(data)

    ack = getLine(peerSocket)
    if ack == "1":
        return 1
    else:
        return 0

def get(hashedKey):
    """
    Returns: the data stored at the key

    Request - from the owner of the hashSpace the key lives in -
    the data stored at that key
    """

    #locate the owner of the hashSpace
    peerIP, peerPort = locate(hashedKey).split(":")

    if contains(hashedKey) != 1:
        return "Error - key doesn't exists".encode()

    peerSocket = socket(AF_INET, SOCK_STREAM)
    peerSocket.connect((peerIP, int(peerPort)))

    #send GET message to the owner
    getMsg = "GET\n"
    peerSocket.send(getMsg.encode())

    #send HashedKey to the owner
    hashedKeyMsg = str(hashedKey) + "\n"
    peerSocket.send(hashedKeyMsg.encode())

    #receive Acknowledgement of spaceOwner
    ackOwner = getLine(peerSocket)

    #if not good, return None
    if ackOwner == "0":
        return None

    #receive integer len from the owner
    dataLen = int(getLine(peerSocket))

    #receive bytearray from the owner
    byteArray = recvAll(peerSocket, dataLen)

    peerSocket.close()

    return byteArray

def contains(hashedKey):
    """
    Returns: 1 if the key exists in the hashSpace
             0 if the key does not exist in the hashSpace
             -1 if ackOwner failed
    """

    #locate the owner of the hashSpace
    peerIP, peerPort = locate(hashedKey).split(":")
    peerSocket = socket(AF_INET, SOCK_STREAM)
    peerSocket.connect((peerIP, int(peerPort)))

    #Send CONTAINS message to the peer
    containsMsg = "CONTAINS\n"
    peerSocket.send(containsMsg.encode())

    #Send HashedKey to the peer
    hashedKeyMsg = str(hashedKey) + "\n"
    peerSocket.send(hashedKeyMsg.encode())

    #Receive Acknowledgement from the peer on space ownership
    ackOwner = getLine(peerSocket)
    if ackOwner == "0":
        peerSocket.close()
        return -1

    #Receive Acknowledgement from the peer on key existence
    ackContains = getLine(peerSocket)
    if ackContains == "1":
        peerSocket.close()
        return 1
    else:
        peerSocket.close()
        return 0

def insert(hashedKey, data):
    """
    Send an entry to the peer who owns the hashSpace

    Returns: 1 if the insert was successful
             0 if the insert failed
             -1 if ackOwner failed
    """

    # locate the owner of the hashSpace
    peerIP, peerPort = locate(hashedKey).split(":")
    peerSocket = socket(AF_INET, SOCK_STREAM)
    peerSocket.connect((peerIP, int(peerPort)))

    #Send INSERT message to the peer
    insertMsg = "INSERT\n"
    peerSocket.send(insertMsg.encode())

    #Send HashedKey to the peer
    hashedKeyMsg = str(hashedKey) + "\n"
    peerSocket.send(hashedKeyMsg.encode())

    #receive Acknowledgement from the peer on space ownership
    ackOwner = getLine(peerSocket)
    if ackOwner == "0":
        peerSocket.close()
        return -1

    #send integer len to the peer
    dataLen = len(data)
    dataLenMsg = str(dataLen) + "\n"
    peerSocket.send(dataLenMsg.encode())

    #send bytearray to the peer
    peerSocket.send(data)

    #receive Acknowledgement from the peer on successful entry
    ackInsert = getLine(peerSocket)
    if ackInsert == "1":
        peerSocket.close()
        return 1
    else:
        peerSocket.close()
        return 0

def remove(hashedKey):
    """
    Request peer to remove an entry living in their hashSpace

    Returns: 1 if the remove was successful
             0 if the remove failed
             -1 if ackOwner failed
    """

    #locate the owner of the hashSpace
    peerIP, peerPort = locate(hashedKey).split(":")
    peerSocket = socket(AF_INET, SOCK_STREAM)
    peerSocket.connect((peerIP, int(peerPort)))

    #Send REMOVE message to the peer
    removeMsg = "REMOVE\n"
    peerSocket.send(removeMsg.encode())

    #Send HashedKey to the peer
    hashedKeyMsg = str(hashedKey) + "\n"
    peerSocket.send(hashedKeyMsg.encode())

    #receive Acknowledgement from the peer on space ownership
    ackOwner = getLine(peerSocket)
    if ackOwner == "0":
        peerSocket.close()
        return -1

    #receive Acknowledgement from the peer on successful removal
    ackRemove = getLine(peerSocket)
    if ackRemove == "1":
        peerSocket.close()
        return 1
    else:
        peerSocket.close()
        return 0

""" Threads """

handler = socket(AF_INET, SOCK_STREAM)
handler.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
handler.bind(('', 0))
handler.listen(16)
handlePort = handler.getsockname()[1]


def handlePeer(conn):
    #handle one connection at a time
    while True:
        peerSocket, peerAddress = conn.accept()
        peerCommand = getLine(peerSocket)

        if peerCommand == "CONNECT":
            handleConnect(peerSocket)
        elif peerCommand == "DISCONNECT":
            handleDisconnect(peerSocket)
        elif peerCommand == "LOCATE":
            handleLocate(peerSocket)
        elif peerCommand == "UPDATE_PREV":
            handleUpdatePrevOnNext(peerSocket)
        elif peerCommand == "GET":
            handleGet(peerSocket)
        elif peerCommand == "CONTAINS":
            handleContains(peerSocket)
        elif peerCommand == "INSERT":
            handleInsert(peerSocket)
        elif peerCommand == "REMOVE":
            handleRemove(peerSocket)

        peerSocket.close()

def fingerReviewer():
    """
    Reviews the finger table every 20 seconds
    """

    while True:
        threading.Event().wait(15)
        print("UPDATING FINGER TABLE")
        reviewFingerTable()

""" Handlers """

## Functions currently do not close sockets

def spaceOwnerAck(peerSocket, hashedKey):
    """
    Quick acknowledgement of space ownership

    Returns: 1 or 0 for an early return
    """

    if hashedSelfAddress == fingerTable["next"][0]:
        #we own everything
        ack = "1\n"
        peerSocket.send(ack.encode())
        return 1
    elif fingerTable["next"][0] < hashedSelfAddress:
        #our owned space wrapped
        #check in front of us and behind next
        if hashedKey > hashedSelfAddress or hashedKey < fingerTable["next"][0]:
            ack = "1\n"
            peerSocket.send(ack.encode())
            return 1
        else:
            ack = "0\n"
            peerSocket.send(ack.encode())
            return 0
    else:
        #our owned space is not wrapped
        if hashedSelfAddress < hashedKey < fingerTable["next"][0]:
            ack = "1\n"
            peerSocket.send(ack.encode())
            return 1
        else:
            ack = "0\n"
            peerSocket.send(ack.encode())
            return 0

def handleConnect(peerSocket):
    global localHashTable

    peerHashedKey = int(getLine(peerSocket))

    # check if we own the space
    if spaceOwnerAck(peerSocket, peerHashedKey) == 0:
        return

    # check how many files the new person will recieve
    hashedNextAddress = fingerTable["next"][0]
    numFiles = sum(1 for hk in localHashTable if peerHashedKey <= hk < hashedNextAddress)
    peerSocket.sendall((str(numFiles) + "\n").encode())

    # send all files in the new persons hash space
    for hk, value in localHashTable.items():
        if peerHashedKey <= hk < hashedNextAddress:
            peerSocket.sendall((hk + "\n").encode())
            peerSocket.sendall((str(len(data)) + "\n").encode())
            peerSocket.sendall(data)

    # send the peerAddress of our next
    peerSocket.sendall((fingerTable["next"][1] + "\n").encode())

    # recieve the peerAddress of the person joining and update our finger table
    newNextPeerAddress = getLine(peerSocket)
    fingerTable["next"] = (peerHashedKey, newNextPeerAddress)

    return

def handleDisconnect(peerSocket):
    global fingerTable, localHashTable

    newNextPeerAddress = getLine(peerSocket)
    temp = newNextPeerAddress.split(":")
    nextIP = temp[0]
    nextPort = int(temp[1])
    fingerTable["next"] = (getHashIndex((nextIP, nextPort)), newNextPeerAddress)

    numFiles = int(getLine(peerSocket))
    for _ in range(numFiles):
        hk = int(getLine(peerSocket)) #          recieve hashedkey
        size = int(getLine(peerSocket)) #   recieve len of byte array
        data = recvAll(peerSocket, size) #        recieve byte array
        localHashTable[hk] = data # store data in our local hashtable

    peerSocket.sendall("1\n".encode())

    if newNextPeerAddress == selfAddress[:-1]:
        fingerTable["prev"] = (hashedSelfAddress, selfAddress[:-1])
        return
    else:
        updatePrevOnNext(newNextPeerAddress)
        return

def handleLocate(peerSocket):
    """
    Handles the LOCATE message from a peer

    Sends the peer the closest finger to the hashedKey
    """

    #receive the hashedKey from the peer
    hashedKey = getLine(peerSocket)
    hashedKey = int(hashedKey)

    #find the closest finger to the hashedKey
    closestFinger = findClosestFinger(hashedKey)

    #send the closest finger to the peer
    closestFingerAddress = fingerTable[closestFinger][1]
    peerSocket.send((closestFingerAddress + "\n").encode())

    return

def handleUpdatePrevOnNext(peerSocket):
    """
    Handles the UPDATE_PREV message from a peer

    Updates local fingerTable with the new prev pee
    """

    #receive the peerAddress from the peer
    peerAddress = getLine(peerSocket)
    tempIP, tempPort = peerAddress.split(":")
    hashedPeerAddress = getHashIndex((tempIP, int(tempPort)))

    try:
        #update local fingerTable with the new prev peer
        fingerTable["prev"] = (hashedPeerAddress, peerAddress)
    except:
        ack = "0\n"
        peerSocket.send(ack.encode())
        return

    #send Acknowledgement to the peer
    ack = "1\n"
    peerSocket.send(ack.encode())
    return

def handleGet(peerSocket):
    """
    Handles the GET message from a peer

    Sends the peer the data stored at the hashedKey
    """

    #receive the hashedKey from the peer
    hashedKey = getLine(peerSocket)
    hashedKey = int(hashedKey)

    #check if we own the hashedKey, acknowledge
    if spaceOwnerAck(peerSocket, hashedKey) == 0:
        return

    data = localHashTable[hashedKey]

    #send the length of the data to the peer
    dataLen = len(data)
    dataLenMsg = str(dataLen) + "\n"
    peerSocket.send(dataLenMsg.encode())

    #send the data to the peer
    peerSocket.send(data)

    return

def handleContains(peerSocket):
    """
    Handles the CONTAINS message from a peer

    Sends the peer an acknowledgement of data existence/ownership
    """

    #receive the hashedKey from the peer
    hashedKey = getLine(peerSocket)
    hashedKey = int(hashedKey)

    # check if we own the hashedKey, acknowledge
    if spaceOwnerAck(peerSocket, hashedKey) == 0:
        return

    #check if the hashedKey exists in the local hashTable
    if hashedKey not in localHashTable:
        #send Acknowledgement of no data existence
        ack = "0\n"
        peerSocket.send(ack.encode())
    else:
        #send Acknowledgement of data existence
        ack = "1\n"
        peerSocket.send(ack.encode())

    return

def handleInsert(peerSocket):
    """
    Handles the INSERT message from a peer

    Inserts the data into the local hashTable
    """

    #receive the hashedKey from the peer
    hashedKey = getLine(peerSocket)
    hashedKey = int(hashedKey)

    # check if we own the hashedKey, acknowledge
    if spaceOwnerAck(peerSocket, hashedKey) == 0:
        return

    #receive the length of the data from the peer
    dataLen = getLine(peerSocket)
    dataLen = int(dataLen)

    #receive the data from the peer
    data = recvAll(peerSocket, dataLen)

    #insert the data into the local hashTable
    localHashTable[hashedKey] = data

    #send Acknowledgement of successful entry
    ack = "1\n"
    peerSocket.send(ack.encode())

    return

def handleRemove(peerSocket):
    """
    Handles the REMOVE message from a peer

    Removes the data from the local hashTable
    """

    #receive the hashedKey from the peer
    hashedKey = getLine(peerSocket)
    hashedKey = int(hashedKey)

    # check if we own the hashedKey, acknowledge
    if spaceOwnerAck(peerSocket, hashedKey) == 0:
        return

    #remove the data from the local hashTable
    localHashTable.pop(hashedKey, None)

    #send Acknowledgement of successful removal
    ack = "1\n"
    peerSocket.send(ack.encode())

    return

""" Starting Point """

#hash our IPAddress
selfAddress = f"{getLocalIPAddress()}:{handlePort}\n"
tempIP, tempPort = selfAddress[:-1].split(":")
hashedSelfAddress = getHashIndex((tempIP, int(tempPort)))

#make listening thread
threading.Thread(target=handlePeer, args=(handler,), daemon=True).start()

#if we are first - start the dht up
if len(sys.argv) < 3:
    #create finger table
    fingerTable["self"] = (hashedSelfAddress, selfAddress[:-1])
    fingerTable["next"] = (hashedSelfAddress, selfAddress[:-1])
    fingerTable["prev"] = (hashedSelfAddress, selfAddress[:-1])

    #populate finger table
    for i in range(1, 5):
        finger = (hashedSelfAddress + i*gap) % (2**160)
        fingerTable[finger] = (hashedSelfAddress, selfAddress[:-1])

else:
    knownPeerIP = sys.argv[1]
    knownPeerPort = int(sys.argv[2])

    #locate the current owner of our space starting from the known peer
    currOwner = locate(hashedSelfAddress, f"{knownPeerIP}:{knownPeerPort}")

    #connect to the current owner
    peerSocket = socket(AF_INET, SOCK_STREAM)
    peerSocket.connect((currOwner.split(":")[0], int(currOwner.split(":")[1])))

    if connect(peerSocket) != 1:
        print("Something went wrong while connecting")

    peerSocket.close()

    #populate finger table
    populateFingerTable()

#start the finger reviewer thread
threading.Thread(target=fingerReviewer, daemon=True).start()

""" User handled in main below """

while True:
    # wait for user input
    userInput = input("Enter command: ").lower()
    key = input("Enter key or leave empty: ")
    hashedKey = getHashIndexString(key)

    #handle user input
    if userInput == "get":
        data = get(hashedKey)
        if data is None:
            print("There was a problem retrieving the data")
        else:
            print("Data: ", data.decode())

    elif userInput == "contains":
        exists = contains(hashedKey)
        if exists == 1:
            print("Key exists")
        elif exists == 0:
            print("Key does not exist")
        else:
            print("There was a problem, possible space ownership issue")

    elif userInput == "insert":
        data = input("Enter data: ")
        result = insert(hashedKey, data.encode())
        if result == 1:
            print("Insert successful")
        elif result == 0:
            print("Insert failed")
        else:
            print("There was a problem, possible space ownership issue")

    elif userInput == "remove":
        result = remove(hashedKey)
        if result == 1:
            print("Remove successful")
        elif result == 0:
            print("Remove failed")
        else:
            print("There was a problem, possible space ownership issue")

    elif userInput == "disconnect":
        prevAddress = fingerTable["prev"][1]
        peerSocket = socket(AF_INET, SOCK_STREAM)
        peerSocket.connect((prevAddress.split(":")[0], int(prevAddress.split(":")[1])))
        result = disconnect(peerSocket)
        if result == 1:
            peerSocket.close()
            handler.close()
            print("Disconnect successful")
            break
        else:
            peerSocket.close()
            print("Disconnect failed, please try again (yes, you are stuck here until it works)")

    elif userInput == "debug":
        print("Finger Table:")
        for finger in fingerTable:
            print(finger, fingerTable[finger])

        print("Local Hash Table:")
        for hk in localHashTable:
            print(hk, localHashTable[hk].decode())

        print("Self Address: ", selfAddress)

    else:
        print("Invalid command")
