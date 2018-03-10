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
    '''
    Make an interface monitor. The following configuration are supported:

    config = {
        'listeners_config': {
            'listeners': <listeners configuration>,
            'addr.inet': 192.168.1.2    # Source IP address to match
        },

        # Mangler config, other than types, other settings may be optional
        'mangler_config': {
            'type': 'DlinkPacketMangler',
            'dlink.src': <source MAC addr>,
            'dlink.dst': <destination MAC addr>,
            'inet.src':  <source IP addr>,
            'inet.dst':  <destination IP addr>,
        },

        'injector_config': {
            'iface': 'en0'                  # interface to inject traffic into
        },

        'iface': 'en0',                     # name of the interface to monitor
        'is_loopback': True|False           # If iface is a loopback interface
        'is_forwarder': Ture|False          # Does this forward traffic?
    }

    TODO: Instead of 'is_loopback' config, try to detect it by 'iface' name

    @param config:  a configuration dictionary
    @param logger:  optional logger
    @return      :  None on error, a monitor object on success
    '''
    logger = logging.getLogger() if logger is None else logger


    monitor_config = dict()
    is_loopback = config.get('is_loopback', None)
    if is_loopback is None:
        logger.error('Bad monitor config: is_loopback keyword required')
        return None

    is_forwarder = config.get('is_forwarder', None)
    if is_forwarder is None:
        logger.error('Bad monitor config: is_forwarder keyword required')
        return None

    # 1. make conditions for a public monitor/forwarder
    lconfig = config.get('listeners_config', dict()).get('listeners', dict())
    ipconf = config.get('listeners_config', dict()).get('ipconf', None)

    conditions = list()

    if ipconf is not None:
        ipcond = condition.IpSrcCondition(ipconf)
        if not ipcond.initialize():
            logger.error('Failed to make IpSrcCondition')
            return None
        conditions.append(ipcond)

    if is_forwarder:
        is_divert = config.get('is_divert', None)
        if is_divert is None and is_forwarder:
            logger.error('Bad monitor config: is_divert keyword required')
            return None

        conds = condition.make_forwarder_conditions(lconfig, is_divert, logger)
        if conds is None:
            logger.error('Failed to make listener conditions for forwarder')
            return None
        conditions.append(conds)

    if len(conditions) <= 0:
        logger.error('Bad config: No conditions')
        return None

    monitor_config['conditions'] = conditions


    # 2. make a mangler
    mconfig = config.get('mangler_config', dict())
    mangler = make_mangler(mconfig)
    if mangler is None:
        logger.error('Failed to make mangler for monitor')
        return None

    monitor_config['mangler'] = mangler

    # 3. make an injector
    iconfig = config.get('injector_config', dict())
    injector = make_injector(iconfig)
    if injector is None:
        logger.error('Failed to make injector for monitor')
        return None
    monitor_config['forwarder'] = injector

    monitor_config['iface'] = config.get('iface', None)
    if is_loopback:
        monitor = LoopbackInterfaceMonitor(monitor_config)
    else:
        monitor = InterfaceMonitor(monitor_config)

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
        'conditions':   [
            condition_object0,
            condition_object1,
        ]
    }
    '''
    START_TIMEOUT = 3

    def __init__(self, config):
        super(InterfaceMonitor, self).__init__(config)
        self.monitor_thread = None
        self.is_running = False
        self.timeout = self.START_TIMEOUT
        self.iface = None
        self.conditions = None
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

        self.conditions = self.config.get('conditions', list())
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

    def is_forward(self, ip_packet):
        pkt = {'raw': ip_packet, 'meta': dict()}
        for c in self.conditions:
            if not c.is_pass(pkt):
                return False
        return True

    def forward(self, ip_packet):
        new_packet = self.mangler.mangle(ip_packet)
        if new_packet is None:
            return False
        return self.forwarder.inject(new_packet)

    def _process(self, bytez):
        ip_packet = self.ip_packet_from_bytes(bytez)
        if ip_packet is None:
            return False

        tport = dutils.tport_from_ippacket(ip_packet)
        if tport is None:
            return False

        if not self.is_forward(ip_packet):
            return False
        return self.forward(ip_packet)

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
