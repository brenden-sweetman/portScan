# Author: Brenden Sweetman
# Title: portScanMultiThreaded
# Description: A lightweight Multi-Threaded port scanner in python2

import struct
import socket
import re
from multiprocessing.pool import ThreadPool as Pool
import time
import argparse

# Method to get IPs from subnet
# Method to get IPs from subnet
# Args: subnet - A sting denoting a IPv4 subnet of form XXX.XXX.XXX.XXX/XX
def getSubnetRange(subnet):
    # Split sting to IP and CIDR
    ip,cidr = subnet.split("/")
    cidr = int(cidr)
    # Unpack network address to an int 
    net = struct.unpack('>I', socket.inet_aton(ip))[0]
    # Get number of local host bits
    hostBits = 32 - cidr
    # Bit shift address to remove local host bits then shift address back
    start = (net >> hostBits) << hostBits
    end = start | ((1 << hostBits) - 1)
    # Iterate through all ints in range and recreate IPs
    return [socket.inet_ntoa(struct.pack('>I',i)) for i in range(start, end)]

# Method to get IPs from IP range
# Args: start - IPv4 range string of form XXX.XXX.XXX.XXX-XXX.XXX.XXX.XXX
def getIPRange(iprange):
    # Split 2 addresses
    start,end = iprange.split("-")
    # Unpack network addresses to an int
    start = struct.unpack(">I", socket.inet_aton(start))[0]
    end = struct.unpack(">I", socket.inet_aton(end))[0]
    # Iterate through all ints in range and recreate IPs
    return [socket.inet_ntoa(struct.pack('>I',i)) for i in range(start,end)]

# Method to perform port test
# Args: request - String of orginal rage subnet, or IP requested in csv
#       host - Tring of Hostname or IP to test connection
#       port - Int of for port used for connection
#       timout - Int Seconds to wait before colosing socket without reply
def testPort(request,host,port,timeout):
    # Create new TCP socket for connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set Timout value on socket to user supplied seconds
    if timeout != None:
        sock.settimeout(timeout)
    else:
        sock.settimeout(10)
    try:
        # Attempt Socket connection on host and port
        result = sock.connect((host,int(port)))
        # If connection was successful:
        if result == None:
            result = "Open"
    # Collect DNS resolve error for hostname
    except socket.gaierror:
        result = "Hostname could not be resolved"
    # Collect timeout error if no reply recived
    except socket.timeout:
        result = "FILTERED"
    # Collect conection refused error if destination replys with a refused ack packet 
    except ConnectionRefusedError:
        result = "NOT LISTENING"
    # Collect and print any other error
    except socket.error as msg:
        result = msg
    sock.close()
    return [request, host, port, result]

# Method to export as csv
# Args: resultList - List of all results from the pool run
#       outFile - File name for output csv
def csvExport(resultList,outFile):
    # Write header for file
    csvOut = "Request, Destination, Port, Result\n"
    # Loop through resultDict collecting values for csv
    for result in resultList:
        csvOut = csvOut + "%s,%s,%s,%s\n" % tuple(result)
    # write csv
    outFile = open(outFile,"w")
    outFile.write(csvOut)
    outFile.close()


# Method to create list of all connections that need to be tested
# Args: inList - list of split lines from input csv
def getDestList(inList):
    destList = []
    # Loop through all input lines
    for inValue in inList:
        # Frist value is hostname, IP, IP range, or subnet to test
        host = inValue[0]
        # Split list of ports
        ports = inValue[1].split(",")
        # If input is range of IPs
        if bool(re.search(r"\d+-\d+", host)):
            ipList = getIPRange(host)
            for ip in ipList:
                for port in ports:
                    destList.append([host,ip,port])
        # If input is a subnet
        elif bool(re.search(r"\d+\/\d+",host)):
            ipList = getSubnetRange(host)
            for ip in ipList:
                for port in ports:
                    destList.append([host,ip,port])
        # If input is a single IP or hostname
        else:
            for port in ports:
                destList.append([host,host,port])
    return destList

# Script Start Piont:
if __name__ == "__main__":
    # Collect start time of script
    startTime = time.time()

    # Parse CMD line args
    parser = argparse.ArgumentParser(description='A lightweight Multi-Threaded port scanner in python2')
    parser.add_argument('input',help='Formated Input File')
    parser.add_argument('output',help='Output File (CSV)')
    parser.add_argument("-t","--timeout",help='Timeout to wait for reply (Seconds). Default 10 Seconds.',type=int)
    parser.add_argument("-p","--poolsize",help='Size of muti-threaded pool. Default 5 threads',type=int)  
    args = parser.parse_args()
    inFile = args.input
    outFile = args.output
    timeout = args.timeout
    poolsize = args.poolsize

    # Read from input file
    destFile = open(inFile,"r")
    inList = []
    for count,line in enumerate(destFile, start=1):
        # Pull out bad chars:
        line = ''.join(c for c in line if 0 < ord(c) < 127)
        # Remove new line and spaces then split between IP/Hostname and ports
        split1 = line.rstrip('\n').split(" ")
        # Test line meets expected format
        if len(split1) != 2 :
            print >> sys.stderr, "ERROR at line " + str(count) + ":[" + line + "]. Skipping. Use -h option for more info"
        else:
            inList.append([split1[0],split1[1]])
    # Create list of all destination connections
    destList = getDestList(inList)
    resultsList = []
    # Create execution pool to test all connections with user supplied number of threads
    if poolsize != None:
        pool = Pool(poolsize)
    else:
        pool = Pool(5)
    # Add and run all connections in pool
    for test in destList:
        resultsList.append(pool.apply_async(testPort, args=tuple(test + [timeout])))
    # End pool
    pool.close()
    pool.join()
    resultsList = [i.get() for i in resultsList]
    # Collect results from pool
    csvExport(resultsList, outFile)
        # Report execution time
    execTime = time.time() - startTime
    print "Execution Time %.2f Seconds" % execTime
