#! python
# Author: Brenden Sweetman
# Title: portScan
# Description: A lightweight port scanner in python


import ipaddress
import re
import sys
import socket

# Method to get IPs from IP range
def getIPRange(start,end):
    startInt = int(ipaddress.ip_address(start).packed.hex(), 16)
    endInt = int(ipaddress.ip_address(end).packed.hex(), 16)
    return [ipaddress.ip_address(ip).exploded for ip in range(startInt,endInt)]

# Method to get IPs from subnet
def getSubnetRange(subnet):
    return [str(ip) for ip in ipaddress.IPv4Network(subnet,False)]


# Method to perform port test
def testPort(host,ports):
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            result = sock.connect((host,int(port)))
            if result == None:
                results.append((port,"Open"))
            sock.close()
        except socket.gaierror:
            results.append((port,"Hostname could not be resolved"))
        except socket.error as msg:
            results.append((port,msg))
    return results

# Method to export as csv
def csvExport(resultDict):
    # Write header for file
    csvOut = "Request, Destination, Port, Result\n"
    # Loop through resultDict collecting values for csv
    for key1 in resultDict:
        for key2 in resultDict[key1]:
            for result in resultDict[key1][key2]:
                csvOut = csvOut + "{},{},{},{}\n".format(key1,key2,result[0],result[1])
    # write csv
    outFile = open("portScanResults.csv","w")
    outFile.write(csvOut)
    outFile.close()


if __name__ == "__main__":
    destFile = open("destFile.txt","r")
    destDict = {}
    for count,line in enumerate(destFile, start=1):
        # Remove new line and spaces then split between IP/Hostname and ports
        split1 = line.rstrip('\n').replace(" ","").split(":")
        # Test line meets expected format
        if len(split1) != 2 :
            print("ERROR at line " + str(count) + ":[" + line + "] use -h option for more info", file=sys.stderr)
            sys.exit("Failed Execution")
        else:
            destDict[split1[0]] = split1[1].split(",")
    resultDict = {}
    for key in destDict:
        # If input is range of IPs
        if bool(re.search(r"\d+-\d+", key)):
            tempSplit = key.split("-")
            ipList = getIPRange(tempSplit[0],tempSplit[1])
            resultDict[key]={}
            for ip in ipList:
                resultDict[key][ip]= testPort(ip,destDict[key])
        # If input is a subnet
        elif bool(re.search(r"\d+\/\d+",key)):
            ipList = getSubnetRange(key)
            resultDict[key]={}
            for ip in ipList:
                resultDict[key][ip] = testPort(ip,destDict[key])
        # If input is a single IP or hostname
        else:
            resultDict[key] = {key: testPort(key,destDict[key])}
    csvExport(resultDict)
