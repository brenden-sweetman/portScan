import struct
import socket
import re
from multiprocessing.pool import ThreadPool as Pool

def getSubnetRange(subnet):
    ip,cidr = subnet.split("/")
    cidr = int(cidr)
    net = struct.unpack('>I', socket.inet_aton(ip))[0]
    hostBits = 32 - cidr
    start = (net >> hostBits) << hostBits
    end = start | ((1 << hostBits) - 1)
    return [socket.inet_ntoa(struct.pack('>I',i)) for i in range(start, end)]

def getIPRange(iprange):
    start,end = iprange.split("-")
    start = struct.unpack(">I", socket.inet_aton(start))[0]
    end = struct.unpack(">I", socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I',i)) for i in range(start,end)]

# Method to perform port test
def testPort(request,host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
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

def csvExport(resultList):
    # Write header for file
    csvOut = "Request, Destination, Port, Result\n"
    # Loop through resultDict collecting values for csv
    for result in resultList:
        csvOut = csvOut + "%s,%s,%s,%s\n".format(*result)
    # write csv
    outFile = open("portScanResults.csv","w")
    outFile.write(csvOut)
    outFile.close()

def getDestList(inList):
    destList = []
    for inValue in inList:
        host = inValue[0]
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

if __name__ == "__main__":
    destFile = open("destFile.txt","r")
    inList = []
    for count,line in enumerate(destFile, start=1):
        # Remove new line and spaces then split between IP/Hostname and ports
        split1 = line.rstrip('\n').replace(" ","").split(":")
        # Test line meets expected format
        if len(split1) != 2 :
            print >> sys.stderr, "ERROR at line " + str(count) + ":[" + line + "] use -h option for more info"
            sys.exit("Failed Execution")
        else:
            inList.append([split1[0],split1[1]])
    destList = getDestList(inList)
    resultsList = []
    pool = Pool(5)
    for test in destList:
        print "Add " + str(test) + " to pool"
        resultsList.append(pool.apply_async(testPort, args=tuple(test)))
    pool.close()
    pool.join()
    resultsList = [i.get() for i in resultsList]
    print resultsList
    #csvExport(resultsList)
