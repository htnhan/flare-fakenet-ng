from diverters import BaseObject, utils as dutils
from scapy.all import TCP, UDP, IP, Ether


def make_mangler(config):
    _map = {
        'TPortMangler': TPortMangler,
        'IPMangler': IPMangler,
        'IPSwapMangler': IPSwapMangler,
        'DlinkPacketMangler': DlinkPacketMangler,
        'SrcIpFwdMangler': SrcIpFwdMangler,
        'DstIpFwdMangler': DstIpFwdMangler,
    }
    _type = config.get('type', None)

    _obj = _map.get(_type, None)
    if _obj is None:
        return None
    
    mangler = _obj(config)
    if not mangler.initialize():
        return None
    
    return mangler



class Mangler(BaseObject):
    '''This is a generic interface for packet mangling'''
    def __init__(self, config):
        super(Mangler, self).__init__(config)
        self.conditions = list()
    
    def initialize(self):
        if not super(Mangler, self).initialize():
            return False
        self.conditions = self.config.get('conditions', None)
        if self.conditions is None:
            return False
        return True

    def mangle(self, pkt):
        if self.is_mangle(pkt):
            return self.do_mangle(pkt.get('raw'))
        return None

    def do_mangle(self, raw):
        '''Mangle an ip packet and return a mangled IP object
        @param raw: Raw SCAPY object
        @return None on error, mangled IP Object on success
        '''
        return raw
    
    def is_mangle(self, pkt):
        for cond in self.conditions:
            if not cond.is_pass(pkt):
                return False
        return True


class TPortMangler(Mangler):
    '''
    This class mangles network data at the transport layer. Currently, no
    changes are needed.
    '''
    def do_mangle(self, ip_packet):
        if TCP in ip_packet:
            return self.mangle_tcp(ip_packet)
        if UDP in ip_packet:
            return self.mangle_udp(ip_packet)
        return None

    def mangle_tcp(self, ip_packet):
        '''
        NOTE: Can we avoid the copy for better performance?
        '''
        otport = ip_packet[TCP]
        ntport = TCP(sport=otport.sport, dport=otport.dport,
                     seq=otport.seq, ack=otport.ack,
                     dataofs=otport.dataofs, window=otport.window,
                     flags=otport.flags,
                     options=otport.options)/otport.payload
        return ntport

    def mangle_udp(self, ip_packet):
        '''NOTE: Can we avoid the copy for better performance?'''
        otport = ip_packet[UDP]
        ntport = UDP(
            sport=otport.sport, dport=otport.dport,
        )/otport.payload
        return ntport


class IPMangler(TPortMangler):
    '''
    This class is used to mangle an IP packet. Supported configuration:
    {
        'inet.dst'      :   New destination IP address
        'inet.src'      :   New source IP address
    }
    This is a subclass of TPortMangler. All options supported by
    TPortMangler are also supported.
    '''
    def __init__(self, config):
        super(IPMangler, self).__init__(config)
        self.REQUIRED_KEYS = []

    def initialize(self):
        if not super(IPMangler, self).initialize():
            return False
            
        keys = self.config.keys()
        for k in self.REQUIRED_KEYS:
            if k not in keys:
                return False
        return True

    def do_mangle(self, ip_packet):
        tport = super(IPMangler, self).do_mangle(ip_packet)
        if tport is None:
            return None
        newdst = self.config.get('inet.dst', ip_packet.dst)
        newsrc = self.config.get('inet.src', ip_packet.src)
        ipkt = IP(id=ip_packet.id, flags=ip_packet.flags,
                  frag=ip_packet.frag, src=newsrc, dst=newdst)/tport
        return ipkt

class IPSwapMangler(IPMangler):
    '''
    Swap the source and destination ip address before mangling. This is
    a subclass of IPMangler. All configs supported by IPMangler are also
    supported.
    '''
    def do_mangle(self, ip_packet):
        ip_packet.src, ip_packet.dst = ip_packet.dst, ip_packet.src
        ipkt = super(IPSwapMangler, self).do_mangle(ip_packet)
        return ipkt


class DlinkPacketMangler(IPMangler):
    '''
    This class is used to mangle data link frame. Supported config:
    {
        'dlink.src'     :   New source hardware/MAC address
        'dlink.dst'     :   New destination hardware/MAC addrses
    }
    This is a subclass of IPMangler. All configs supported by IPMangler
    are also supported.
    '''
    def __init__(self, config):
        super(DlinkPacketMangler, self).__init__(config)
        self.REQUIRED_KEYS.append('dlink.src')
        self.REQUIRED_KEYS.append('dlink.dst')

    def inititlize(self):
        if not super(DlinkPacketMangler, self).initialize():
            return False
        return True

    def do_mangle(self, ip_packet):
        macsrc = self.config.get('dlink.src')
        macdst = self.config.get('dlink.dst')
        nipkt = super(DlinkPacketMangler, self).do_mangle(ip_packet)
        dlink = Ether(src=macsrc, dst=macdst)/nipkt
        return dlink

class IpForwardMangler(TPortMangler):
    '''
    This class implements NAT and Reverse NAT mangling. Supported configuration:
    {
        'inet.dst'      :   New destination IP address
        'inet.src'      :   New source IP address
    }
    This is a subclass of TPortMangler. All options supported by
    TPortMangler are also supported.
    '''

    def __init__(self, config):
        super(IpForwardMangler, self).__init__(config)
        self._tbl = None

    def initialize(self):
        if not super(IpForwardMangler, self).initialize():
            return False
        
        self._tbl = self.config.get('ip_forward_table', None)
        if self._tbl is None:
            self.logger.error('Failed! ip_forward_table is required')
            return False
        return True

    
class SrcIpFwdMangler(IpForwardMangler):    
    def do_mangle(self, ip_packet):
        tport = super(SrcIpFwdMangler, self).do_mangle(ip_packet)
        if tport is None:
            return None

        dendpoint = dutils.gen_endpoint_key_from_ippacket_dst(ip_packet)
        new_src = self._tbl.get(dendpoint, ip_packet.src)
        ipkt = IP(id=ip_packet.id, flags=ip_packet.flags,
                  frag=ip_packet.frag, src=new_src, dst=ip_packet.dst)/tport
        return ipkt


class DstIpFwdMangler(IpForwardMangler):    
    def do_mangle(self, ip_packet):
        tport = super(DstIpFwdMangler, self).do_mangle(ip_packet)
        if tport is None:
            return None

        sendpoint = dutils.gen_endpoint_key_from_ippacket_src(ip_packet)
        new_dst = self.config.get('inet.dst', ip_packet.dst)
        self._tbl[sendpoint] = ip_packet.dst
        ipkt = IP(id=ip_packet.id, flags=ip_packet.flags,
                  frag=ip_packet.frag, src=ip_packet.src, dst=new_dst)/tport
        return ipkt        
