import threading
import traceback
import pcapy
import logging

from diverters import BaseObject
from diverters.mangler import make_mangler
from diverters.injector import make_injector
from diverters import condition
from diverters import utils as dutils
from scapy.all import Ether, IP



def make_monitor(config, logger=None):
    mtype = config.get('type')
    if mtype == 'LoopbackInterfaceMonitor':
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


class InterfaceMonitor(BaseObject):
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
        self.mangler = None

    def initialize(self):
        if not super(InterfaceMonitor, self).initialize():
            return False

        self.iface = self.config.get('iface', None)
        if self.iface is None:
            self.logger.error('Bad config: iface key required')
            return False

        #self.mangler = make_mangler(self.config.get('mangler', dict()))
        self.mangler = self.config.get('mangler', None)
        if self.mangler is None:
            self.logger.error('Bad mangler config')
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
        newpkt = self.mangler.mangle(pkt)
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
