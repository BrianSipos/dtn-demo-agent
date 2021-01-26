''' BP-specific field types.
'''
''' Items related to per-block data.
'''
import datetime
import enum
import logging
import urllib
from scapy import volatile
from scapy_cbor.fields import (CborField, UintField)

LOGGER = logging.getLogger(__name__)


class EidField(CborField):
    ''' A structured representation of an Endpoint ID.
    Only specific URI schemes are encodable.
    '''

    @enum.unique
    class TypeCode(enum.IntFlag):
        ''' EID scheme codes.
        Flags must be in LSbit-first order.
        '''
        dtn = 1
        ipn = 2

    class WellKnownSsp(enum.IntFlag):
        ''' Integer-valued well-known SSP.
        '''
        none = 0

    def i2m(self, pkt, x):
        if x is None or x == 'dtn:none':
            return [EidField.TypeCode.dtn, EidField.WellKnownSsp.none]

        parts = urllib.parse.urlsplit(x)
        try:
            scheme_type = EidField.TypeCode[parts[0]]
        except KeyError:
            raise ValueError('No type code for scheme "{}"'.format(parts[0]))

        authority = parts[1]
        path = parts[2]
        ssp = ''
        if authority:
            ssp += '//' + authority
            if not path.startswith('/'):
                path = '/' + path
        ssp += path

        return [scheme_type, ssp]

    def m2i(self, pkt, x):
        if x is None:
            return None
        if isinstance(x, str):
            return x

        scheme_type = x[0]
        ssp = x[1]
        if isinstance(ssp, int):
            ssp = EidField.WellKnownSsp(ssp).name

        return '{0}:{1}'.format(
            EidField.TypeCode(scheme_type).name,
            ssp
        )

    def randval(self):
        nodename = volatile.RandString(50)
        servname = volatile.RandString(50)
        return 'dtn://{0}/{1}'.format(nodename, servname)


class DtnTimeField(UintField):
    ''' A DTN time value.
    This value is automatically converted from a
    :py:cls:`datetime.datetime` object and text.
    '''

    #: Epoch reference for DTN Time
    DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    @staticmethod
    def datetime_to_dtntime(val):
        if val is None:
            return 0
        delta = val - DtnTimeField.DTN_EPOCH
        return int(delta / datetime.timedelta(milliseconds=1))

    @staticmethod
    def dtntime_to_datetime(val):
        if val == 0 or val is None:
            return None
        delta = datetime.timedelta(milliseconds=val)
        return delta + DtnTimeField.DTN_EPOCH

    def i2h(self, pkt, x):
        dtval = DtnTimeField.dtntime_to_datetime(x)
        if dtval is None:
            return None
        return dtval.isoformat()

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def h2i(self, pkt, x):
        return self.any2i(pkt, x)

    def any2i(self, pkt, x):
        if x is None:
            return None

        elif isinstance(x, datetime.datetime):
            return DtnTimeField.datetime_to_dtntime(x)

        elif isinstance(x, (str, bytes)):
            return DtnTimeField.datetime_to_dtntime(
                datetime.datetime.fromisoformat(x)
                    .replace(tzinfo=datetime.timezone.utc)
            )

        return int(x)

    def randval(self):
        return volatile.RandNum(-(2 ** 16), (2 ** 16))
