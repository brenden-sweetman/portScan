#! python
# Author: Brenden Sweetman
# Title: portScan
# Description: A lightweight port scanner in python


import ipaddress
import re
import sys
import socket


def testPort(host,ports):
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            print ("connection on "+ host + ":" + str(port))
            result = sock.connect((host,int(port)))
            print ("Result: " + str(result))
            if result == None:
                results.append((port,"Open"))
            sock.close()
        except socket.gaierror:
            results.append((port,"Hostname could not be resolved"))
        except socket.error as msg:
            results.append((port,"Could not connect to remote host: {}".format(msg)))
    return results


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
    print (destDict)
    resultDict = {}
    for key in destDict:
        resultDict[key] = testPort(key,destDict[key])
    print (resultDict)
