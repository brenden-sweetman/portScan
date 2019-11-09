# Author: Brenden Sweetman
# Title: portScanMultiThreadedcsv
# Description: A lightweight Multi-Threaded port scanner in python with CSV support


import ipaddress
import re
import sys
import socket
import argparse
from multiprocessing.pool import ThreadPool
import time



# Method to get IPs from IP range
# Args: start - IPv4 sting of form XXX.XXX.XXX.XXX
#       end - ""
def getIPRange(start,end):
    # Convert first and last IP into integers 
    startInt = int(ipaddress.ip_address(start).packed.hex(), 16)
    endInt = int(ipaddress.ip_address(end).packed.hex(), 16)
    # Interate over range of ints repacking back into IP stings
    return [ipaddress.ip_address(ip).exploded for ip in range(startInt,endInt+1)]

# Method to get IPs from subnet
# Args: subnet - A sting denoting a IPv4 subnet of form XXX.XXX.XXX.XXX/XX
def getSubnetRange(subnet):
    # Iterate over all IP in supplied subnet
    return [str(ip) for ip in ipaddress.IPv4Network(subnet,False)]


# Method to perform port test
# Args: request - String of orginal rage subnet, or IP requested in csv
#       host - Tring of Hostname or IP to test connection
#       port - Int of for port used for connection
#       otherInfo - A list of other information from the original csv
#       timeout - Number of seconds to wait with no reply
def testPort(request,host,port,otherInfo,timeout):
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
            result = " LISTENING"
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
    # Close socket and end connection
    sock.close()
    # Return results
    return [request, host, port, result] + otherInfo

# Method to export as csv
# Args: resultList - List of all results from the pool run
#       outFile - File name for output csv
def csvExport(resultList,outFile):
    # Write header for file
    csvOut = "Request,Destination,Port,Result,Service,Item Number,Rule Identifier,Description\n"
    # Loop through resultDict collecting values for csv
    for result in resultList:
        csvOut = csvOut + "{0},{1},{2},{3},{4},{5},{6},{7}\n".format(*result)
    # Write to csv
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
        ports = inValue[1].split(";")
        # Keep track of other info in input csv
        otherInfo = inValue[2:6]
        # If input is range of IPs
        if bool(re.search(r"\d+-\d+", host)):
            # Split start and end addesses
            tempSplit = host.split("-")
            ipList = getIPRange(tempSplit[0],tempSplit[1])
            for ip in ipList:
                for port in ports:
                    destList.append([host,ip,port] + otherInfo)
        # If input is a subnet
        elif bool(re.search(r"\d+\/\d+",host)):
            ipList = getSubnetRange(host)
            for ip in ipList:
                for port in ports:
                    destList.append([host,ip,port] + otherInfo)
        # If input is a single IP or hostname
        else:
            for port in ports:
                destList.append([host,host,port] + otherInfo) 
    return destList

# Script Start Piont:
if __name__ == "__main__":
    # Collect start time of script
    startTime = time.time()
    # Parse CMD line args
    parser = argparse.ArgumentParser(description='A lightweight Multi-Threaded port scanner in python')
    parser.add_argument('input',help='Formated Input File')
    parser.add_argument('output',help='Output File (CSV)')
    parser.add_argument("-t","--timeout",help='Timeout to wait for reply (Seconds). Default 10 Seconds.',type=int)
    parser.add_argument("-p","--poolsize",help='Size of muti-threaded pool. Default 5 threads',type=int)
    args = parser.parse_args()
    inFile = args.input
    outFile = args.output
    timeout = args.timeout
    poolsize = args.poolsize

    # Read from input csv
    destFile = open(inFile,"r")
    inList = []
    for count,line in enumerate(destFile, start=1):
        # Pull out bad chars:
        line = ''.join(c for c in line if 0 < ord(c) < 127)
        split1 = line.rstrip('\n').split(",")
        # Test line meets expected format
        if len(split1) != 6:
            print ("Bad Line Detected: {}".format(line))
        else:
            inList.append(split1)
    #Remove first line of csv
    inList.pop(0)
    # Create list of all destination connections
    destList = getDestList(inList)
    resultsList = []
    # Create execution pool to test all connections with user supplied number of threads
    if poolsize != None:
        pool = ThreadPool(poolsize)
    else:
        pool = ThreadPool(5)
    # Add and run all connections in pool
    for test in destList:
        resultsList.append(pool.apply_async(testPort, args=(test[0],test[1],test[2],test[3:7],timeout)))
    # End pool
    pool.close()
    pool.join()
    # Collect results from pool
    resultsList = [i.get() for i in resultsList]
    # Write results to csv
    csvExport(resultsList,outFile)
    # Report execution time
    execTime = time.time() - startTime
    print("Execution Time {:.2f} Seconds".format(execTime))
