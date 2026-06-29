from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_TIME_EXCEEDED = 11

# RTT summary stats (bonus)
rtt_list = []
packets_sent = 0
packets_received = 0


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
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        # Fetch the ICMP header from the IP packet
        # IP header is the first 20 bytes; ICMP header starts at byte 20
        ipHeader = recPacket[:20]
        ip_fields = struct.unpack("!BBHHHBBH4s4s", ipHeader)
        ttl = ip_fields[5]

        icmpHeader = recPacket[20:28]
        icmpType, icmpCode, icmpChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        # Check if this is our echo reply
        if icmpType == ICMP_ECHO_REPLY and packetID == ID:
            # Extract the timestamp from the payload (after the 8-byte ICMP header)
            timeSent = struct.unpack("d", recPacket[28:36])[0]
            rtt = (timeReceived - timeSent) * 1000  # in milliseconds
            return rtt, sequence, ttl

        # Bonus: ICMP Error Parsing
        elif icmpType == ICMP_DEST_UNREACH:
            unreach_codes = {
                0: "Destination Network Unreachable",
                1: "Destination Host Unreachable",
                2: "Destination Protocol Unreachable",
                3: "Destination Port Unreachable",
                4: "Fragmentation Required",
                5: "Source Route Failed",
            }
            msg = unreach_codes.get(icmpCode, f"Destination Unreachable (code {icmpCode})")
            return f"ICMP Error: {msg}"

        elif icmpType == ICMP_TIME_EXCEEDED:
            if icmpCode == 0:
                return "ICMP Error: TTL Expired in Transit"
            else:
                return "ICMP Error: Fragment Reassembly Time Exceeded"
        # Fill in end

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(str(header + data))

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout):
    global packets_sent, packets_received

    icmp = getprotobyname("icmp")

    # Fill in start
    # Create a raw socket for ICMP
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    # Fill in end

    myID = os.getpid() & 0xFFFF

    # Fill in start
    # Send a single ping using the socket, dst addr and ID
    packets_sent += 1
    sendOnePing(mySocket, destAddr, myID)

    # Wait for reply using timeout
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    # Close the socket
    mySocket.close()
    # Fill in end

    return delay


def ping(host, timeout=2):
    global rtt_list, packets_sent, packets_received

    dest = gethostbyname(host)
    print(f"Pinging {dest} ({host}) using Python:")
    print("")

    seq = 1
    try:
        while 1:
            result = doOnePing(dest, timeout)

            if isinstance(result, tuple):
                # Successful reply: (rtt, sequence, ttl)
                rtt, sequence, ttl = result
                packets_received += 1
                rtt_list.append(rtt)
                print(f"Reply from {dest}: seq={seq} TTL={ttl} time={rtt:.2f} ms")
            else:
                # Timeout or ICMP error string
                print(f"seq={seq} — {result}")

            seq += 1
            time.sleep(1)

    except KeyboardInterrupt:
        # Bonus: RTT Summary Stats
        print("\n--- Ping Statistics ---")
        print(f"Packets: Sent = {packets_sent}, Received = {packets_received}, "
              f"Lost = {packets_sent - packets_received} "
              f"({(packets_sent - packets_received) / packets_sent * 100:.1f}% loss)")
        if rtt_list:
            print(f"RTT (ms): Min = {min(rtt_list):.2f}, Max = {max(rtt_list):.2f}, "
                  f"Avg = {sum(rtt_list)/len(rtt_list):.2f}")
        print("")


ping("google.com")
