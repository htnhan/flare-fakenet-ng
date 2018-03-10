'''
PoC for darwin diverter.
'''

import logging
import traceback
import subprocess as sp

from expiringdict import ExpiringDict
from time import sleep
from scapy.all import conf
from diverters import Diverter
from diverters import utils as dutils
from diverters.monitor import make_monitor

from diverters.condition import make_forwarder_conditions
from diverters.condition import IpSrcCondition, DirectionCondition
from diverters.injector import make_injector
from diverters.mangler import make_mangler
from diverters.monitor import LoopbackInterfaceMonitor, InterfaceMonitor

def make_diverter(dconf, lconf, lvl):
    config = {
        'listeners_config': lconf,
        'diverter_config': dconf,
        'log_level': lvl
    }
    diverter = DarwinUserlandDiverter(config)
    if not diverter.initialize():
        return None
    return diverter


ADDR_LINK_ANY = 'ff:ff:ff:ff:ff:ff'
LOOPBACK_IP = '127.0.0.1'
MY_IP = '192.0.2.123'
MY_IP_FAKE = '192.0.2.124'
LOOPBACK_IFACE = 'lo0'


class DarwinDiverter(Diverter):
    def __init__(self, config):
        super(DarwinDiverter, self).__init__(config)
    
    def initialize(self):
        if not super(DarwinDiverter, self).initialize():
            return False
        
        self.gw = dutils.get_gateway_info()
        if self.gw is None:
            self.logger.error('Failed to get gateway info')
            return False

        self.iface = dutils.get_iface_info(self.gw.get('iface'))
        if self.iface is None:
            self.logger.error('Failed to get public interface info')
            return False

        return True


class DarwinUserlandDiverter(DarwinDiverter):
    def __init__(self, config):
        super(DarwinUserlandDiverter, self).__init__(config)
        self.loopback_ip = MY_IP
        self.loopback_ip_fake = MY_IP_FAKE
        self.gw = None
        self.iface = None
        self.configs = dict()
        self.devnull = open('/dev/null', 'rw+')
        self.is_running = False

        self.public_forwarder = None
        self.public_monitor = None
        self.local_fowarder = None
        self.local_monitor = None

    def initialize(self):
        '''
        Initialize method. This MUST be called right after object
        creation.
        @return True on sucess, False if error occurs
        '''

        if not super(DarwinUserlandDiverter, self).initialize():
            return False

        if not self.initialize_public_forwarder():
            self.logger.error('Failed to initialize public forwarder')
            return False

        if not self.initialize_public_monitor():
            self.logger.error('Failed to initialize public monitor')
            return False

        if not self.initialize_local_forwarder():
            self.logger.error('Failed to initialize local forwarder')
            return False

        if not self.initialize_local_monitor():
            self.logger.error('Failed to initialize local monitor')
            return False

        # disable scapy.runtime debug log to make things quieter
        logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
        return True


    def initialize_public_forwarder(self):
        '''Initialize the public interface forwarder. This forwarder
        monitors the loopback interface and forward any traffic
        passing proper Conditions to the public interface.
        @return   : True on success, False on failure
        @attention: Sets the self.public_forwarder object
        '''

        # Step 1: make conditions
        conditions = list()
        ipcond = IpSrcCondition({
            'addr.inet': [self.loopback_ip]
        })
        if not ipcond.initialize():
            return False
        conditions.append(ipcond)

        conds = make_forwarder_conditions(
            self.listeners_config, False, self.logger
        )
        if conds is None:
            return False
        conditions.append(conds)

        # Step 2: make mangler
        mangler = make_mangler({
            'type': 'DlinkPacketMangler',
            'dlink.src': self.iface.get('addr.dlink'),
            'dlink.dst': self.gw.get('addr.dlink'),
            'inet.src': self.iface.get('addr.inet'),
            'conditions': conditions,
        })
        if mangler is None:
            return False

        forwarder = make_injector({'iface': self.iface.get('iface')})
        if forwarder is None:
            return False

        # Actually initialize the loopback interface monitor
        monitor_config = {
            'manglers': [mangler],
            'forwarder': forwarder,
            'iface': LOOPBACK_IFACE,
            'type': 'LoopbackInterfaceMonitor'
        }

        monitor = make_monitor(monitor_config, self.logger)
        if monitor is None:
            self.logger.error('Failed to make monitor')
            return False

        self.public_forwarder = monitor
        return True

    def initialize_public_monitor(self):
        '''
        Initialize the public interface monitor. This monitor watches
        the machine public interface and forward traffic matching the
        Conditions to the loopback interface.
        @return     : True on success, False on failure
        @attention  : Sets the self.public_monitor object
        '''

        ipcond = IpSrcCondition({
            'addr.inet': self.iface.get('addr.inet'),
            'not': True,
        })
        if not ipcond.initialize():
            return False
        conditions = [ipcond]

        # Step 2: make mangler
        mangler = make_mangler({
            'type': 'IPMangler',
            'inet.dst': self.loopback_ip,
            'conditions': conditions,
        })
        if mangler is None:
            return False

        forwarder = make_injector({
            'iface': LOOPBACK_IFACE,
            'type': 'LoopbackInjector',
        })
        if forwarder is None:
            return False

        monitor_config = {
            'manglers': [mangler],
            'forwarder': forwarder,
            'iface': self.iface.get('iface'),
            'type': 'InterfaceMonitor',
        }

        monitor = make_monitor(monitor_config, self.logger)
        if monitor is None:
            self.logger.error('Failed to make monitor')
            return False
        self.public_monitor = monitor
        return True

    def initialize_local_forwarder(self):
        '''
        Initialize the local interface forwarder. This forwarder
        monitors the loopback interface and forward traffic passing
        certain Conditions back into the loopback interface after
        mangling the packets.
        @return     : True on sucess, False on failure
        @attention  : Sets the self.local_forwarder object
        '''

        # Step 1: Make conditions
        conditions = list()

        ipcond = IpSrcCondition({'addr.inet': [self.loopback_ip]})
        if not ipcond.initialize():
            return False
        
        conds = make_forwarder_conditions(
            self.listeners_config, True, self.logger
        )
        if conds is None:
            return False
        conditions = [ipcond, conds]

        mangler = make_mangler({
            'type': 'IPSwapMangler',
            'inet.dst': self.loopback_ip_fake,
            'conditions': conditions,
        })
        if mangler is None:
            return False

        forwarder = make_injector({
            'iface': LOOPBACK_IFACE,
            'type': 'LoopbackInjector'
        })
        if forwarder is None:
            return False

        monitor_config = {
            'manglers': [mangler],
            'forwarder': forwarder,
            'iface': LOOPBACK_IFACE,
            'type': 'LoopbackInterfaceMonitor',
        }

        monitor = make_monitor(monitor_config, self.logger)
        if monitor is None:
            return False

        self.local_forwarder = monitor
        return True


    def initialize_local_monitor(self):
        '''
        Initialize the loopback interface monitor. This monitor watches
        the loopback interface, and mangle the traffic that match
        certain conditions before injecting it back into the loopback
        interface
        @return     : True on success, False on failure
        @attention  : Set self.local_monitor object
        '''
        ipcond = IpSrcCondition({'addr.inet': [self.loopback_ip_fake]})
        if not ipcond.initialize():
            return False
        conditions = [ipcond]

        mangler = make_mangler({
            'type': 'IPSwapMangler',
            'inet.dst': self.loopback_ip,
            'conditions': conditions,
        })
        if mangler is None:
            return False

        forwarder = make_injector({
            'iface': LOOPBACK_IFACE,
            'type': 'LoopbackInjector',
        })
        if forwarder is None:
            return False

        monitor_config = {
            'manglers': [mangler],
            'forwarder': forwarder,
            'iface': LOOPBACK_IFACE,
            'type': 'LoopbackInterfaceMonitor',
        }

        monitor = make_monitor(monitor_config, self.logger)
        if monitor is None:
            return False
        self.local_monitor = monitor
        return True

    def start(self):
        '''Start the diverter
        @return True on sucess, False on failure
        '''
        self.logger.error('Diverter starting...')
        if not self._save_config():
            self.logger.error('Save config failed')
            return False

        if not self._change_config():
            self.logger.error('Change config failed')
            return False

        self.public_monitor.start()
        self.public_forwarder.start()
        self.local_monitor.start()
        self.local_forwarder.start()
        self.is_running = True
        self.logger.error('Diverter started')
        return True

    def stop(self):
        '''
        This method should always return True
        @return True on sucess, False on failure.
        '''

        self.is_running = False
        self.public_monitor.stop()
        self.public_forwarder.stop()
        self.local_monitor.stop()
        self.local_forwarder.stop()
        self._restore_config()
        return True

    # -----------------------------------------------------------------
    # Internal methods, do not call!
    # -----------------------------------------------------------------
    def _change_config(self):
        '''
        Apply the following network configuration changese:
        - Add an IP alias to the loopback interface.
        - Change the default gateway to the newly alias IP.
        - Enable forwarding if it is currently disabled.
        @return True on sucess, False on failure.
        '''
        if len(self.configs) <= 0:
            if not self._save_config():
                self.logger.error('Save config failed')
                return False
        if not self._add_loopback_alias():
            self.logger.error('Failed to add loopback alias')
            return False
        if not self._change_default_route():
            self.logger.error('Failed to change default route')
            return False
        return True


    def _save_config(self):
        '''
        Save the following network configuration:
        - net.inet.ip.forwarding
        - Current default gateway
        @return True on sucess, False on failure.
        '''
        configs = dict()
        try:
            ifs = sp.check_output('sysctl net.inet.ip.forwarding',
                                  shell=True, stderr=self.devnull)
            _,v = ifs.strip().split(':', 2)
            v = int(v, 10)
        except:
            self.logger.error('Save config failed')
            return False
        configs['net.forwarding'] = v

        try:
            iface, ipaddr, gw = conf.route.route('0.0.0.0')
        except:
            return False
        configs['net.iface'] = iface
        configs['net.ipaddr'] = ipaddr
        configs['net.gateway'] = gw
        self.configs = configs
        return True

    def _add_loopback_alias(self):
        '''Try to execute all commands. Only return success if all commands are
        executed successfully
        '''
        cmds = [
            'ifconfig lo0 alias %s' % (self.loopback_ip,),
            'ifconfig lo0 alias %s' % (self.loopback_ip_fake,),
        ]
        for cmd in cmds:
            if not self._quiet_call(cmd):
                return False
        return True

    def _change_default_route(self):
        '''
        Try to change the default route. If that fails, add a default route
        to the specified IP address
        '''
        cmds = [
            'route -n change default %s' % (self.loopback_ip,),
            'route -n add default %s' % (self.loopback_ip,),
        ]
        for cmd in cmds:
            if self._quiet_call(cmd):
                return True
        return False


    def _restore_config(self):
        '''
        Restore the following network settings. This should always
        return True
        - Default route
        - Remove loopback IP aliases
        @return True on sucess, False on failure.
        '''
        if len(self.configs) == 0:
            return True
        self._fix_default_route()
        self._remove_loopback_alias()
        return True

    def _remove_loopback_alias(self):
        cmds = [
            'ifconfig lo0 -alias %s' % (self.loopback_ip,),
            'ifconfig lo0 -alias %s' % (self.loopback_ip_fake,)
        ]
        for cmd in cmds:
            if not self._quiet_call(cmd):
                return False
        return True

    def _fix_default_route(self):
        gw = self.configs.get('net.gateway', None)
        if gw is None:
            return self._quiet_call('route -n delete default')
        return self._quiet_call('route -n change default %s'% (gw,))


    def _quiet_call(self, cmd):
        '''
        Simple wrapper to execute shell command quietly
        @attention: Is shell=True a security concern?
        '''
        try:
            sp.check_call(cmd,
                          stdout=self.devnull,
                          stderr=sp.STDOUT,
                          shell=True)
        except:
            self.logger.error('Failed to run: %s' % (cmd,))
            stk = traceback.format_exc()
            self.logger.debug(">>> Stack:\n%s" % (stk,))
            return False
        return True
