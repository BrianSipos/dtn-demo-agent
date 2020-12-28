''' Session and Transfer extension type definitions.
'''
from . import formats
from .messages import SessionExtendHeader, TransferExtendHeader


@SessionExtendHeader.bind_extension(0xFF)
class SessionPrivateDummy(formats.NoPayloadPacket):
    ''' Example of session extension. '''
    fields_desc = [
        formats.UInt64Field('largeval', default=0),
        formats.UInt16Field('smallval', default=0),
    ]


@TransferExtendHeader.bind_extension(0xFF)
class TransferPrivateDummy(formats.NoPayloadPacket):
    ''' Example of session extension. '''
    fields_desc = [
        formats.UInt64Field('largeval', default=0),
        formats.UInt16Field('smallval', default=0),
    ]


@TransferExtendHeader.bind_extension(0x01)
class TransferTotalLength(formats.NoPayloadPacket):
    ''' Identify total transfer (bundle) length. '''
    fields_desc = [
        formats.UInt64Field('total_length', default=None),
    ]
