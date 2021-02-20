''' Base class and registrar.
'''
import dbus.service

#: Dictionary of BP applications
APPLICATIONS = {}


def app(path: str):
    ''' Decorator to register a CL adaptor class.
    :param str path: DBus object path to register.
    '''

    def func(cls):
        if path in APPLICATIONS:
            raise KeyError('Duplicate app path: {}'.format(path))
        APPLICATIONS[path] = cls
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
