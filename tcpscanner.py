import optparse
from socket import *

def connScan(tgtHost, tgtPort):
    """ Will attempt to connect to the given host through the provided port and inform
    if the port is open or closed """
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        print '[+]%d/tcp open' % tgtPort
    except:
        print '[-]%d/tcp closed' % tgtPort


def portScan(tgtHost, tgtPorts):
    """ Will go through all of the tgtPorts to check if they're open or closed """
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host" % tgtHost
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print '\n[+] Scan Results for: ' + tgtName[0]
    except:
        print '\n[+] Scan Results for: ' + tgtIP

    setdefaulttimeout(1)
    for port in tgtPorts:
        print 'Scanning port ' + port
        connScan(tgtHost, int(port))


def main():

    parser = optparse.OptionParser('usage %prog -t <target host> -p <target port>')

    parser.add_option('-t', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='int', help='specify target port')

    options, args = parser.parse_args()

    tgtHost = options.tgtHost
    tgtPort = options.tgtPort

    if tgtHost == None or tgtPort == None:
        print parser.usage
        exit(0)

if __name__ == '__main__':
    main()
