import threading
import traceback
import pcapy
import logging

import subprocess as sp
import json


from time import sleep

from ctypes import CDLL, Structure, sizeof, byref, create_string_buffer
from ctypes import c_ubyte, c_ushort, c_int, c_uint, c_ulong, c_char, c_void_p
from socket import SOCK_STREAM

from diverters import BaseObject
from diverters import utils as dutils
from scapy.all import Ether, IP, TCP, UDP



def make_monitor(config, logger=None):
    mtype = config.get('type')
    if mtype == 'KextMonitor':
        monitor = KextMonitor(config)
    elif mtype == 'LoopbackInterfaceMonitor':
        monitor = LoopbackInterfaceMonitor(config)
    elif mtype == 'InterfaceMonitor':
        monitor = InterfaceMonitor(config)
    else:
        logger.error('Bad type: %s' % (mtype,))
        return None

    if not monitor.initialize():
        logger.error('Failed to initialize InterfaceMonitor')
        return None

    return monitor



class TrafficMonitor(BaseObject):
    '''
    This class monitors provides a uniformed API to monitor network traffic and
    make decisions on whether or not to mangle the traffic.

    The following config is supported:
        'manglers':  [mangler_object],
    }
    '''

    START_TIMEOUT = 3
    def __init__(self, config):
        super(TrafficMonitor, self).__init__(config)
        self.conditions = None
        self.manglers = list()
        self.monitor_thread = None
        self.timeout = self.START_TIMEOUT
        self.is_running = False
    

    def initialize(self):
        if not super(TrafficMonitor, self).initialize():
            return False
        
        self.manglers = self.config.get('manglers', None)
        if self.manglers is None or len(self.manglers) <= 0:
            self.logger.error('Bad mangler config')
            return False

        return True

    def mangle(self, pkt):
        for mangler in self.manglers:
            newpkt = mangler.mangle(pkt)
            if newpkt is not None:
                return newpkt
        return None


class InterfaceMonitor(TrafficMonitor):
    '''
    This class monitors and injects traffic to the specified network interface
    after mangling the network data. The monitor only captures and injects
    traffic matching the specified set of conditions. The following config
    is supported:
    config = {
        'iface'     :    'en0',                 # name of an interface
        'forwarder' :    <an injector object>,
    }
    '''
    START_TIMEOUT = 3

    def __init__(self, config):
        super(InterfaceMonitor, self).__init__(config)
        self.monitor_thread = None
        self.is_running = False
        self.timeout = self.START_TIMEOUT
        self.iface = None
        self.forwarder = None

    def initialize(self):
        if not super(InterfaceMonitor, self).initialize():
            return False

        self.iface = self.config.get('iface', None)
        if self.iface is None:
            self.logger.error('Bad config: iface key required')
            return False

        self.manglers = self.config.get('manglers', None)
        if self.manglers is None:
            self.logger.error('Bad manglers config')
            return False

        self.forwarder = self.config.get('forwarder', None)
        if self.forwarder is None:
            self.logger.error('Bad config: forwarder key required')
            return False

        return True

    def start(self):
        e = threading.Event()
        e.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_thread,
                                               args=[e])
        self.monitor_thread.start()
        rc = e.wait(self.timeout)
        return rc

    def stop(self):
        self.is_running = False
        if self.monitor_thread is None:
            return True
        rc = self.monitor_thread.join(self.timeout)
        return rc

    def ip_packet_from_bytes(self, bytez):
        try:
            eframe = Ether(bytez)
            ipkt = eframe[IP]
        except:
            return None
        return ipkt

    def _process(self, bytez):
        ip_packet = self.ip_packet_from_bytes(bytez)
        if ip_packet is None:
            return False

        tport = dutils.tport_from_ippacket(ip_packet)
        if tport is None:
            return False

        pkt = {'raw': ip_packet, 'meta': dict()}
        newpkt = self.mangle(pkt)
        if newpkt is None:
            return False
        return self.forwarder.inject(newpkt)

    def _monitor_thread(self, e):
        try:
            pc = pcapy.open_live(self.iface, 0xffff, 1, 1)
        except:
            traceback.print_exc()
            self.is_running = False
            return

        self.is_running = True
        e.set()
        while self.is_running:
            _ts, bytez = pc.next()
            self._process(bytez)
        return


class LoopbackInterfaceMonitor(InterfaceMonitor):
    def ip_packet_from_bytes(self, bytez):
        '''
        Mac returns a different packet format when sniffing a loopback
        intreface. The first 4-bytes are set to "\x02\x00\x00\x00" to
        indicate this IP packet comes from a loopback interface. To
        properly parse the data, we skip the first 4bytes
        '''
        if len(bytez) <= 0:
            return None

        try:
            ipkt = IP(bytez[4:])
        except:
            traceback.print_exc()
            return None
        return ipkt


class KextMonitor(TrafficMonitor):
    PF_SYSTEM = 32
    SYSPROTO_CONTROL = 2
    AF_SYS_CONTROL = 2
    CTLIOCGINFO = c_ulong(3227799043)
    MYCONTROLNAME = "com.mandiant.FakeNetDiverter"
    MAX_PKT_JSON = 1024
    OPTNEXTPKT = 1
    OPTINJECTPKT = 2
    OPTDROPPKT = 3
    OPTENABLESWALLOW = 4
    OPTDISABLESWALLOW = 5
    LIB_SYSTEM_PATH = "/usr/lib/libSystem.B.dylib"
    KEXT_PATH = "/Users/me/FakeNetDiverter.kext"

    class sockaddr_ctl(Structure):
        _fields_ = [('sc_len', c_ubyte),
                    ('sc_family', c_ubyte),
                    ('ss_sysaddr', c_ushort),
                    ('sc_id', c_uint),
                    ('sc_unit', c_uint),
                    ('sc_reserved', c_uint * 5)]

    class ctl_info(Structure): 
        _fields_ = [('ctl_id', c_uint),
        ('ctl_name', c_char * 96)]
    

    def __init__(self, config):
        super(KextMonitor, self).__init__(config)
        self.posix = None
    
    def __del__(self):
        self.__unload_kext()

    def initialize(self):
        if not super(KextMonitor, self).initialize():
            return False
            
        self.posix = self.__initialize_posix_wrapper()
        if self.posix is None:
            self.logger.error('Failed to initialize POSIX wrapper')
            return False

        if not self.__load_kext():
            return False

        return True
    
    def start(self):
        self.is_running = True
        self.socket = self.__initialize_socket()

        if self.socket is None:
            return False
        
        e = threading.Event()
        e.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_thread,
                                               args=[e])
        self.monitor_thread.start()
        rc = e.wait(self.timeout)
        return rc
    
    def stop(self):
        self.logger.error('Stopping')
        self.is_running = False
        if self.monitor_thread is None:
            return True
        rc = self.monitor_thread.join(self.timeout)
        self.posix.close(self.socket)
        self.socket = None
        self.posix = None
        self.__unload_kext()
        return rc

    # internal
    def __initialize_posix_wrapper(self):
        posix = CDLL(self.LIB_SYSTEM_PATH, use_errno=True)
        posix.getsockopt.argtypes = [c_int, c_int, c_int, c_void_p, c_void_p]
        posix.setsockopt.argtypes = [c_int, c_int, c_int, c_void_p, c_uint]
        return posix

    def __initialize_socket(self):
        posix = self.posix
        if posix is None:
            return None
        socket = posix.socket(
            self.PF_SYSTEM, SOCK_STREAM, self.SYSPROTO_CONTROL)

        addr = self.sockaddr_ctl()
        addr.sc_len = (c_ubyte)(sizeof(self.sockaddr_ctl))
        addr.sc_family = (c_ubyte)(self.PF_SYSTEM)
        addr.ss_sysaddr = (c_ushort)(self.AF_SYS_CONTROL)

        info = self.ctl_info()
        info.ctl_name = self.MYCONTROLNAME

        rc = posix.ioctl(socket, self.CTLIOCGINFO, byref(info))
        if rc == -1:
            self.logger.error('Failed to query info')
        

        addr.sc_id = (c_uint)(info.ctl_id)
        addr.sc_unit = (c_uint)(0)
        posix.connect(socket, byref(addr), sizeof(addr))
        return socket
    
    def __load_kext(self):
        try:
            sp.call("kextutil %s" % (self.KEXT_PATH,), shell=True)
        except:
            return False
        return True

    def __unload_kext(self):
        if self.socket is not None and self.posix is not None:
            self.posix.close(self.socket)
            self.posix = None
            self.socket = None

        count = 2
        while count > 0:
            try:
                self.logger.error("Unloading kext...")
                x = sp.call("kextunload %s" % (self.KEXT_PATH,), shell=True)
            except:
                return False
            sleep(1)
            count -= 1
        return True
    

    def _monitor_thread(self, event):
        event.set()
        
        self.logger.info("Enabling SWALLOW flag")
        self.posix.setsockopt(
            self.socket, self.SYSPROTO_CONTROL, self.OPTENABLESWALLOW, 0, 0)
        while self.is_running:
            pktSize = c_uint(self.MAX_PKT_JSON)
            pkt = create_string_buffer("\x00" * self.MAX_PKT_JSON)
            self.posix.getsockopt(self.socket,
                                  self.SYSPROTO_CONTROL,
                                  self.OPTNEXTPKT, pkt, byref(pktSize))

            try:
                if len(pkt.value) > 0:
                    pktjson = json.loads(pkt.value)
                    newpkt = self.__process(pktjson)
                    if newpkt is None:
                        pkt = byref(c_uint(int(pktjson.get('id'))))
                        pktSize = c_uint(4)
                        self.logger.error('Dropping bad packets')
                        self.posix.setsockopt(self.socket,
                                              self.SYSPROTO_CONTROL,
                                              self.OPTDROPPKT, pkt, pktSize)
                    newjson = json.dumps(newpkt)
                    newjson += '\0x00'
                    newpkt = create_string_buffer(newjson)

                    pktSize = c_uint(len(newpkt))

                    self.posix.setsockopt(self.socket,
                                          self.SYSPROTO_CONTROL,
                                          self.OPTINJECTPKT, newpkt, pktSize)
            except:
                traceback.print_exc()
        self.posix.setsockopt(self.socket,
                              self.SYSPROTO_CONTROL,
                              self.OPTDISABLESWALLOW, 0, 0)
        return

    def __process(self, pkt):
        direction = pkt.get('direction')
        pktid = pkt.get('id')
        ip_packet = self.ip_packet_from_json(pkt)
        if ip_packet is None:
            self.logger.error('ip_packet is None')
            return None

        packet = {'raw': ip_packet, 'meta': pkt}
        newpkt = self.mangle(packet)
        if newpkt is None:
            newpkt = {'id': pktid, 'changed': False}
        else:
            out =  self.json_from_ip_packet(newpkt, direction, pktid)
            pkt.update(out)
            pkt.update({'changed': True})
        return pkt
    
    def ip_packet_from_json(self, js):
        proto = js.get('proto', None)
        sport = js.get('srcport')
        dport = js.get('dstport')
        src = js.get('srcaddr')
        dst = js.get('dstaddr')
        if proto is None or sport is None or dport is None or src is None or dst is None:
            return None
        
        if proto == 'tcp':
            tport = TCP(sport=sport, dport=dport)
        elif proto == 'udp':
            tport = UDP(sport=sport, dport=dport)
        else:
            tport is None        
        if tport is None:
            return None
        
        ip_packet = IP(src=src, dst=dst)/tport
        return ip_packet

    def json_from_ip_packet(self, ip_packet, direction, pktid):
        tport = dutils.tport_from_ippacket(ip_packet)
        if tport is None:
            ip_packet.show()
        proto = tport.name.lower()
        return {
            u'id': pktid,
            u'direction': direction,
            u'proto': proto,
            u'srcport': tport.sport,
            u'dstport': tport.dport,
            u'srcaddr': ip_packet.src,
            u'dstaddr': ip_packet.dst,
            u'ip_ver': 4,
        }
    
    def drop(self, pkt):
        self.logger.debug("Dropping %s" % (json.dumps(pkt),))
        pkt = byref(c_uint(int(pkt.get('id', -1))))
        pktSize = c_uint(4)
        self.posix.setsockopt(self.socket, self.SYSPROTO_CONTROL,
                              self.OPTDROPPKT, pkt, pktSize)
        return True