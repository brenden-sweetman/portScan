#! python
# Author: Brenden Sweetman
# Title: portScanMultiThreaded
# Description: A lightweight Multi-Threaded port scanner in python


import ipaddress
import re
import sys
import socket
from multiprocessing.pool import ThreadPool

# Method to get IPs from IP range
def getIPRange(start,end):
    startInt = int(ipaddress.ip_address(start).packed.hex(), 16)
    endInt = int(ipaddress.ip_address(end).packed.hex(), 16)
    return [ipaddress.ip_address(ip).exploded for ip in range(startInt,endInt)]

# Method to get IPs from subnet
def getSubnetRange(subnet):
    return [str(ip) for ip in ipaddress.IPv4Network(subnet,False)]


# Method to perform port test
def testPort(request,host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        result = sock.connect((host,int(port)))
        if result == None:
            result = "Open"
    except socket.gaierror:
        result = "Hostname could not be resolved"
    except socket.error as msg:
        result = msg
    return [request, host, port, result]
    sock.close()

# Method to export as csv
def csvExport(resultList):
    # Write header for file
    csvOut = "Request, Destination, Port, Result\n"
    # Loop through resultDict collecting values for csv
    for result in resultList:
        csvOut = csvOut + "{0},{1},{2},{3}\n".format(*result)
    # write csv
    outFile = open("portScanResults.csv","w")
    outFile.write(csvOut)
    outFile.close()

# Method to create list of all connections that need to be tested
def getDestList(inList):
    destList = []
    for inValue in inList:
        host = inValue[0]
        ports = inValue[1].split(",")
        # If input is range of IPs
        if bool(re.search(r"\d+-\d+", host)):
            tempSplit = host.split("-")
            ipList = getIPRange(tempSplit[0],tempSplit[1])
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

if __name__ == "__main__":
    destFile = open("destFile.txt","r")
    inList = []
    for count,line in enumerate(destFile, start=1):
        # Remove new line and spaces then split between IP/Hostname and ports
        split1 = line.rstrip('\n').replace(" ","").split(":")
        # Test line meets expected format
        if len(split1) != 2 :
            print("ERROR at line " + str(count) + ":[" + line + "] use -h option for more info", file=sys.stderr)
            sys.exit("Failed Execution")
        else:
            inList.append([split1[0],split1[1]])
    destList = getDestList(inList)
    resultsList = []
    pool = ThreadPool(5)
    for test in destList:
        resultsList.append(pool.apply_async(testPort, args=tuple(test)))
    pool.close()
    pool.join()
    resultsList = [i.get() for i in resultsList]
    csvExport(resultsList)
