from scapy.all import TCP, UDP
import subprocess as sp
import netifaces
import hashlib


def tport_from_ippacket(ip_packet):
    '''
    Return the transport object (either TCP or UDP) from scappy IP object
    @param ip_packet: scapy IP packet object
    @return None on error, TCP or UDP on success
    '''
    tport = None
    try:
        if UDP in ip_packet:
            tport = ip_packet[UDP]
        elif TCP in ip_packet:
            tport = ip_packet[TCP]
        else:
            tport = None
    except:
        tport = None
    return tport


def gethash(s):
    '''
    Calculate the hash of the input string like data
    @return hashstring
    '''
    md = hashlib.md5()
    md.update(s)
    return md.hexdigest()




def get_iface_info(ifname):
    '''Gather interface information using its name
    @return dictionary {
        'addr.inet':    list of IP addrseses assigned to this interface,
        'addr.dlink':   hardware/MAC address of this interface
        'iface':        interface name
        } or None if error occurs
    '''
    if ifname not in netifaces.interfaces():
        return None

    addrs = netifaces.ifaddresses(ifname)
    ipaddrs = [_.get('addr') for _ in addrs.get(netifaces.AF_INET, dict())]
    if len(ipaddrs) < 1:
        return None

    hwaddr = addrs.get(netifaces.AF_LINK, list())[0].get('addr', None)
    if hwaddr is None:
        return None
    return {'addr.inet': ipaddrs, 'addr.dlink': hwaddr, 'iface': ifname}


def get_gateway_info():
    '''
    Gather default gateway information
    @return dictionary {
        'addr.inet'     :   Gateway IP address
        'addr.dlink'    :   Gateway hardware/MAC address
        'iface'         :   Interface to communicate with default gateway
    } or None if error occurs
    '''
    gwlist = netifaces.gateways().get('default', None)
    if gwlist is None:
        return None
    inetgw = gwlist.get(netifaces.AF_INET, None)
    if inetgw is None:
        return None

    gwip, gwif = inetgw[0], inetgw[1]
    ifinfo = get_iface_info(gwif)
    if ifinfo is None:
        return None
    p = sp.Popen('arp -n %s' % gwip, shell=True, stdout=sp.PIPE)
    (output, _) = p.communicate()
    if 'no entry' in output:
        return None
    try:
        gwmac = output.split(' ')[3]
    except:
        return None
    return {'iface': gwif, 'addr.inet': gwip, 'addr.dlink': gwmac}

def gen_endpoint_key(tport, ip, port):
    return '%s://%s:%s' % (str(tport), str(ip), str(port))

def gen_endpoint_key_from_ippacket_src(ip_packet):
    tport = tport_from_ippacket(ip_packet)
    if tport is None:
        return None
    return gen_endpoint_key(tport.name, ip_packet.src, tport.sport)

def gen_endpoint_key_from_ippacket_dst(ip_packet):
    tport = tport_from_ippacket(ip_packet)
    if tport is None:
        return None
    return gen_endpoint_key(tport.name, ip_packet.dst, tport.dport)
