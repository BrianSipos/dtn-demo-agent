''' Base class and registrar.
'''
import dbus.service
from bp.encoding import (
    AbstractBlock, PrimaryBlock, CanonicalBlock,
)

#: Dictionary of BP applications
APPLICATIONS = {}


def app(name: str):
    ''' Decorator to register a CL adaptor class.
    :param str name: Unique application name.
    '''

    def func(cls):
        if name in APPLICATIONS:
            raise KeyError('Duplicate app name: {}'.format(name))
        APPLICATIONS[name] = cls
        return cls

    return func


class AbstractApplication(dbus.service.Object):
    ''' Base class for bundle application delivery.
    '''

    def __init__(self, agent, bus_kwargs):
        dbus.service.Object.__init__(self, **bus_kwargs)
        self._agent = agent

    def load_config(self, config):
        ''' Read any needed configuration data.
        
        :param config: The agent configuration.
        :type config: :py:cls:`bp.config.Config`.
        '''
        return

    def add_chains(self, rx_chain, tx_chain):
        ''' Add steps to either processing chain.
        
        :param rx_chain: The list of :py:cls:`util.ChainStep`.
        :param tx_chain: The list of :py:cls:`util.ChainStep`.
        '''
        return

    def _recv_for(self, ctr, dest_eid):
        if 'deliver' not in ctr.actions:
            return False
        if ctr.bundle.primary.destination != dest_eid:
            return False
        if ctr.bundle.primary.bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT:
            return False
        return True