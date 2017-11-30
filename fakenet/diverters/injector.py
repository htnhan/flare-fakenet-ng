from diverters import BaseObject
from scapy.all import sendp


def make_injector(config):
    _map = {
        'Injector': Injector,
        'LoopbackInjector': LoopbackInjector,
    }
    _type = config.get('type', 'Injector')
    _obj = _map.get(_type, Injector)
    injector = _obj(config)

    if not injector.initialize():
        return None
    return injector



class Injector(BaseObject):
    '''This object injects network traffic into the specified interface'''

    def initialize(self):
        if not super(Injector, self).initialize():
            return False

        self.ifname = self.config.get('iface', None)
        if self.ifname is None:
            return False

        return True

    def inject(self, ip_packet):
        sendp(ip_packet, iface=self.ifname, verbose=False)
        return True


class LoopbackInjector(Injector):
    '''
    This class is used to inject traffic to the loopback interface on a Mac. On
    Darwin platform (Mac OS), loopback interface does not contains an ethernet
    frame, but contains a special header for IP packets.
    '''
    LOOPBACK_BYTE_HEADER = '\x02\x00\x00\x00'
    def inject(self, ip_packet):
        '''@override'''
        data = self.LOOPBACK_BYTE_HEADER + str(ip_packet)
        sendp(data, iface=self.ifname, verbose=False)
        return True
