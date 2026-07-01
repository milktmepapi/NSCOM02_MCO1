from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
seq = 0 # Added for incrementation

# For bonus; summary statistics
totalSent = 0
totalReceived = 0
rttList = []

# For bonus; error parsin
ICMP_ERROR_MESSAGES = {
    3: {
        0: "Destination Network Unreachable",
        1: "Destination Host Unreachable",
        2: "Destination Protocol Unreachable",
        3: "Destination Port Unreachable",
        4: "Fragmentation Needed and DF set",
        5: "Source Route Failed",
        6: "Destination Network Unknown",
        7: "Destination Host Unknown",
        9: "Network Administratively Prohibited",
        10: "Host Administratively Prohibited",
        13: "Communication Administratively Prohibited",
    },
    11: {
        0: "TTL Expired in Transit",
        1: "Fragment Reassembly Time Exceeded",
    },
}

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
    
    
def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."
        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        #Fill in start
        print("Packet received from:", addr) # Debug
        #Fetch the ICMP header from the IP packet
        # First 20 bytes = IP header (no options), next 8 bytes = ICMP header
        icmpHeader = recPacket[20:28]
        icmpType, code, recvChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        if packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            rtt = (timeReceived - timeSent) * 1000  # convert seconds -> ms
            return sequence, rtt
        #Fill in end

        # Bonus fill in start
        if icmpType in (3, 11):
            # Original packet: 20 bytes (inner IP header) + 8 bytes (inner ICMP header)
            innerIcmpHeader = recPacket[28+20:28+20+8]
            if len(innerIcmpHeader) == 8:
                _, _, _, innerID, innerSeq = struct.unpack("bbHHh", innerIcmpHeader)
                if innerID == ID:
                    description = ICMP_ERROR_MESSAGES.get(icmpType, {}).get(
                        code, f"Unknown ICMP Error (Type={icmpType}, Code={code})"
                    )
                    return "ICMP_ERROR", icmpType, code, description

        # Bonus fill in end
        
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0 # Og version
    # Make a dummy header with a 0 checksum

    global seq # Changed seq here
    seq += 1
    
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq) # Changed seq here
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum((header + data).decode("latin-1")) # Added decode here

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq) # Changed seq here
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout):
    global totalSent, totalReceived, rttList # For bonus
    
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details: http://sockraw.org/papers/sock_raw
    
    #Fill in start
    #create socket
    mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

    #Fill in end
    myID = os.getpid() & 0xFFFF # Return the current process i

    #Fill in start

    #send a single ping using the socket, dst addr and ID
    sendOnePing(mySocket, destAddr, myID)
    
    totalSent += 1  # Bonus; track every request we send
    
    #add delay using timeout
    result = receiveOnePing(mySocket, myID, timeout, destAddr)
    
    #close socket
    mySocket.close()

    if result == "Request timed out.":
        delay = result
    elif isinstance(result, tuple) and result[0] == "ICMP_ERROR":
        # Bonus; ICMP error parsing 
        _, errType, errCode, description = result
        delay = f"ICMP Error: {description} (Type={errType}, Code={errCode})"
    else:
        sequence, rtt = result
        totalReceived += 1 # Bonus; count successful replies
        rttList.append(rtt) # Bonus; collect RTT for summary stats
        delay = f"Sequence={sequence}  RTT={rtt:.2f} ms"
   #Fill in end

    return delay

# Bonus method
def printSummary():
    # Bonus; RTT summary stats prints min/max/avg RTT and packet loss %
    print("")
    print("--- Ping Statistics ---")
    lossRate = 0.0
    if totalSent > 0:
        lossRate = ((totalSent - totalReceived) / totalSent) * 100
    print(f"Packets: Sent = {totalSent}, Received = {totalReceived}, "
          f"Lost = {totalSent - totalReceived} ({lossRate:.2f}% loss)")
 
    if rttList:
        print(f"RTT (ms): Min = {min(rttList):.2f}, "
              f"Max = {max(rttList):.2f}, "
              f"Avg = {sum(rttList)/len(rttList):.2f}")
    else:
        print("RTT (ms): N/A (no successful replies)")
    
    
def ping(host, timeout=2): # Timeout is 2 = 2000ms per the specs
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    
    # Send ping requests to a server separated by approximately one second
    try: 
        while 1 :
            delay = doOnePing(dest, timeout)
            print(delay)
            time.sleep(1)# one second
        return delay
    except KeyboardInterrupt:
        # Bonus; print RTT summary stats when the user stops the ping (Ctrl+C)
        printSummary()

    return
    
if __name__ == "__main__":
    ping("127.0.0.1")