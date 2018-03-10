
import subprocess as sp
import json
import threading
import logging
import traceback

from diverters import BaseObject, utils as dutils
from expiringdict import ExpiringDict


KEY_PROCESS_BLACKLIST = 'processblacklist'
KEY_PROCESS_WHITELIST = 'processwhitelist'


def make_forwarder_conditions(listeners_config, is_divert, logger=None,
                              isProcNameResolved=False):
    '''
    Make the conditions for a monitor/forwarder.
    @param  listeners_config        : listener configs, as a dictionary
    @param  is_divert (True|False)  : The process names are blacklisted/ignored
    @param  logger (OPTIONAL)       : a Logger to use, None to use default
    @return                         : None on error, condition object on success
    '''
    logger = logging.getLogger() if logger is None else logger
    conditions = list()
    for lname, lconfig in listeners_config.iteritems():
        logger.debug('Initializing listener config for %s' % (lname,))

        port_condition = make_listener_port_condition(lconfig, logger)
        if port_condition is None:
            _err = 'Failed to initialize port condition for %s' % (lname,)
            logger.error(_err)
            return None

        blprocs = lconfig.get(KEY_PROCESS_BLACKLIST, '').split(',')
        blprocs = [_.strip() for _ in blprocs]
        if len(blprocs) > 0:
            # if diverting, the process name is blacklisted/ignored
            pnames_cond = make_procnames_condition(blprocs, logger, is_divert, isProcNameResolved)
            if pnames_cond is None:
                return None
            cond = AndCondition({'conditions': [port_condition, pnames_cond]})
            if not cond.initialize():
                _err = 'Failed to make condition for %s config' % (lname,)
                logger.error(_err)
                return None
        conditions.append(cond)

    listener_conditions = OrCondition({'conditions': conditions})
    if not listener_conditions.initialize():
        return None
    return listener_conditions


def make_listener_port_condition(lconfig, logger=None, negate=False):
    '''
    Make the condition for destination port based on a listner config.
    @param lconfig          : dictionary of listener config
    @param logger (OPTIONAL): Logger to use
    @param negate           : Negate the condition, default to False
    @return                 : condition on success, None on error
    '''
    logger = logging.getLogger() if logger is None else logger

    portstring = lconfig.get('port', None)
    if portstring is None:
        return None

    try:
        port = int(portstring)
    except ValueError:
        return None

    pcond = DstPortCondition({'ports': [port], 'not': negate})
    if not pcond.initialize():
        return None
    return pcond


def make_procnames_condition(proc_names, logger=None, negate=False, isProcNameResolved=False):
    '''
    Make a ProcessNamesCondition with provided names.
    @param proc_names           : comma separated list of process names
    @param logger (OPTIONAL)    : Logger to use,
    @param nagate               : True|False flag, negate the condition
    @return                     : condition on success, None on error
    '''
    logger = logging.getLogger() if logger is None else logger
    procs = [name.strip() for name in proc_names]
    if len(procs) <= 0:
        return None
    if not isProcNameResolved:
        cond = ProcessNamesCondition({'process_names': procs, 'not': negate})
    else:
        cond = ResolvedProcessNamesCondition({
            'process_names': procs, 'not': negate,
        })
    if not cond.initialize():
        logger.error('Failed to initialize ProcessNameCondition')
        return None
    return cond


class Condition(BaseObject):
    '''
    This is a generic class to match a network packet against a predefined
    condition. This class expects a dictionary configuration. The following base
    config is supported:
    {
        'not': True,         # negate the rule
        'default_pass': True # default behavior on unexpected input
    }
    '''

    def __init__(self, config):
        super(Condition, self).__init__(config)
        self.negate = self.config.get('not', False)
        self.default = self.config.get('default_pass', False)

    def is_pass(self, pkt):
        raise NotImplementedError


class IpCondition(Condition):
    '''
    This class is a condition to match both source and destination IP address
    from an IP packet. The following configuration is supported:
    {
        'addr.inet': [
            '127.0.0.1',
            '8.8.8.8',
        ]
    }
    '''
    def __init__(self, config):
        super(IpCondition, self).__init__(config)
        self.addrs = list()

    def initialize(self):
        if not super(IpCondition, self).initialize():
            return False

        addrs = self.config.get('addr.inet', list())
        if len(addrs) < 0:
            self.logger.error('Bad config: inet.adds')
            return False

        # A set has better performance when it comes to matching
        self.addrs = set(addrs)
        return True

    def is_pass(self, pkt):
        '''@override'''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        try:
            rc = raw.src in self.addrs or raw.dst in self.addrs
        except:
            rc = self.default
        return rc if not self.negate else not rc


class IpSrcCondition(IpCondition):
    def is_pass(self, pkt):
        '''@override'''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        try:
            rc = raw.src in self.addrs
        except:
            rc = self.default
        return rc if not self.negate else not rc


class IpDstCondition(IpCondition):
    def is_pass(self, pkt):
        '''@override'''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        try:
            rc = raw.dst in self.addrs
        except:
            rc = self.default
        return rc if not self.negate else not rc


class PortCondition(Condition):
    '''
    This class is a condition to match both source and destination ports.
    The following configuration is supported:
    {
        'ports': [21, '22'],
    }
    '''
    def __init__(self, config):
        super(PortCondition, self).__init__(config)
        self.ports = list()

    def initialize(self):
        if not super(PortCondition, self).initialize():
            return False

        try:
            ports = [int(_) for _ in self.config.get('ports', list())]
        except:
            error = "%s\nInvalid port config" % (traceback.format_exc(),)
            self.logger.error(error)
            return False
        self.ports = set(ports)
        return True

    def is_pass(self, pkt):
        '''@override'''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        tport = dutils.tport_from_ippacket(raw)
        if tport is None:
            return self.default
        rc = tport.dport in self.ports or tport.sport in self.ports
        return rc if not self.negate else not rc

class DstPortCondition(PortCondition):
    def is_pass(self, pkt):
        '''@override'''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        tport = dutils.tport_from_ippacket(raw)
        if tport is None:
            return self.default
        rc = tport.dport in self.ports
        return rc if not self.negate else not rc


class SrcPortCondition(PortCondition):
    def is_pass(self, pkt):
        '''@override'''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        tport = dutils.tport_from_ippacket(raw)
        if tport is None:
            return self.default
        rc = tport.sport in self.ports
        return rc if not self.negate else not rc


class CompoundCondition(Condition):
    '''This class is a compound class, matching multiple conditions.
    The following configuration is supported:
    config = {
        'conditions': [
            cond_obj1, cond_obj2, cond_obj3
        ]
    }
    '''
    def __init__(self, config):
        super(CompoundCondition, self).__init__(config)
        self.conditions = list()

    def initialize(self):
        if not super(CompoundCondition, self).initialize():
            return False

        self.conditions = self.config.get('conditions', list())
        if len(self.conditions) <= 0:
            return False

        for cond in self.conditions:
            if not isinstance(cond, Condition):
                return False

        return True

class AndCondition(CompoundCondition):    
    def is_pass(self, pkt):
        '''@override'''
        rc = True
        for cond in self.conditions:
            if not cond.is_pass(pkt):
                rc = False
                break
        return rc if not self.negate else not rc


class OrCondition(CompoundCondition):
    def is_pass(self, pkt):
        rc = False
        for cond in self.conditions:
            if cond.is_pass(pkt):
                rc = True
                break
        return rc if not self.negate else not rc


class MatchAllCondition(Condition):
    '''This class match all packts. No configuration is required'''
    def is_pass(self, pkt):
        '''@override'''
        return True


class MatchNoneCondition(Condition):
    '''This class match none of the packets. No configuration is required'''
    def is_pass(self, pkt):
        '''@override'''
        return False


class ProcessNamesCondition(Condition):
    '''
    This condition match network traffic generated by specific procss names.
    This condition starts a new background dtrace procses to monitor network
    and processes. The following configuration is supported:
    {
        'process_names': [
            'nc',                   # netcat
            'com.apple.WebKit',     # safari
        ]
    }
    '''
    TCPINIT_WAIT_SECONDS = 1
    MAX_AGE_SECONDS = 3
    MAX_LENGTH = 0xff
    DTRACE_SCRIPT = './conn_monitor.d'
    TCP_SYN_FLAG = 0x02

    def __init__(self, config):
        super(ProcessNamesCondition, self).__init__(config)
        self.connecting = ExpiringDict(max_len=self.MAX_LENGTH,
                                       max_age_seconds=self.MAX_AGE_SECONDS)
        self.dtrace_script = self.config.get('dtrace_script',
                                             self.DTRACE_SCRIPT)
        self.dtrace = None
        self.pchild = None
        self.dtrace_done = False
        self.worker_thread = None
        self.tcpinitevent = threading.Event()
        self.connected = ExpiringDict(max_len=self.MAX_LENGTH,
                                      max_age_seconds=self.MAX_AGE_SECONDS)

    def initialize(self):
        if not super(ProcessNamesCondition, self).initialize():
            return False

        self.dtrace_done = False
        dtrace = sp.Popen(['dtrace', '-C', '-s', self.dtrace_script],
                          stdout=sp.PIPE, stderr=sp.PIPE)
        self.dtrace = dtrace
        t = threading.Thread(target=self.__dtrace_monitor_thread,
                             args=[self.dtrace.stdout])
        t.start()
        self.logger.debug("Monitor thread started")
        return True

    def is_tcp_init(self, tport):
        try:
            return not (tport.flags & self.TCP_SYN_FLAG) == 0
        except:
            return False
        return False

    def _get_init_id(self, ip, tport):
        return "%d:%s:%s" % (ip.id, ip.dst, tport.dport)

    def _get_session_id(self, ip, tport):
        return '%s:%d_%s:%d' % (ip.src, tport.sport, ip.dst, tport.dport)

    def is_pass(self, pkt):
        '''
        This condition 'negate' option is handled differently from the rest, and
        therefore deserves some explanation. Others 'negate' option is check at
        the end of their is_pass() API to either return True or False. However,
        this condition 'negate' option is check when a record is seen from
        dtrace, which is procssed in __process() internal function instead.

        @override
        '''
        raw, meta = pkt.get('raw'), pkt.get('meta')
        tport = dutils.tport_from_ippacket(raw)
        is_tcp_init = self.is_tcp_init(tport) if tport is not None else False
        rc = False
        if is_tcp_init:
            if len(self.connecting) <= 0:
                # queue is empty, wait
                self.tcpinitevent.clear()
                self.tcpinitevent.wait(self.TCPINIT_WAIT_SECONDS)

            rc = False
            idstr = self._get_init_id(raw, tport)
            md = dutils.gethash(idstr)

            if self.connecting.get(md, False):
                del self.connecting[md]
                newid = self._get_session_id(raw, tport)
                self.connected[dutils.gethash(newid)] = True
                self.logger.debug('New connection: %s' % (newid,))
                rc = True
        else:
            idstr = self._get_session_id(raw, tport)
            md = dutils.gethash(idstr)
            rc = self.connected.get(md, False)
            if rc:
                self.connected[md] = True # Must update the expire timer
        return rc

    def __dtrace_monitor_thread(self, stdout):
        '''
        Worker thread to monitor dtrace script.
        '''
        self.logger.debug("running monitor thread")
        while not self.dtrace_done:
            line = stdout.readline()
            if len(line) == 0:
                return False

            line = line.strip()
            try:
                js = json.loads(line)
                self.__process(js)
            except:
                pass
        return True

    def __process(self, js):
        '''
        This method process the dtrace script output to add a new entry
        into the list of allowed connection. Dtrace output is expected
        to be in JSON format.
        @return True on success, False on failure
        '''
        names = self.config.get('process_names', list())
        name = js.get('name', '')
        if not self.negate:
            if not name in names:
                self.tcpinitevent.set()
                return True
            pktid = js.get('pktid')
            md = dutils.gethash(pktid)
            if js.get('connecting') is not None:
                self.connecting[md] = True
                self.tcpinitevent.set()
                return True
        else:
            if not name in names:
                pktid = js.get('pktid')
                md = dutils.gethash(pktid)
                if js.get('connecting') is not None:
                    self.connecting[md] = True
                    self.tcpinitevent.set()
                    return True
            else:
                self.tcpinitevent.set()
                return True
        # We should never reach here
        return False


    def __del__(self):
        self.dtrace_done = True
        self.dtrace.terminate()


class ResolvedProcessNamesCondition(Condition):
    def initialize(self):
        if not super(ResolvedProcessNamesCondition, self).initialize():
            return False
        
        self.names = self.config.get('process_names', list())
        return True
    
    def is_pass(self, pkt):
        raw, meta = pkt.get('raw'), pkt.get('meta')
        name = meta.get('procname', None)
        if name is None:
            return False
        
        rc = name in self.names
        return rc if not self.negate else not rc
        
class DirectionCondition(Condition):
    def initialize(self):
        self.direction = self.config.get('direction', 'in')
        return True
    
    def is_pass(self, pkt):
        raw, meta = pkt.get('raw'), pkt.get('meta')
        if meta.get('direction', None) == self.direction:
            return True
        return False