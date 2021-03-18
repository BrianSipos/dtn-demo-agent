''' Conversion and output utilites.
'''
import binascii
import cbor2
import copy
import enum
import six


def encode_diagnostic(obj, **kwargs):
    ''' Encode a Python object as a CBOR Extended Diagnostic Notation string.
    
    :param kwargs: Special options:
      indent: if provided, indent this many spaces
      bstr_as: either 'hex' (default) or 'base64'
    :throw TypeError: If there is an unencodable part.
    '''
    indent = kwargs.get('indent')
    wsp_indent = ' ' * indent if indent is not None else ''

    if isinstance(obj, cbor2.CBORTag):
        text = '{}({})'.format(obj.tag, obj.value)
    elif isinstance(obj, list):
        nextkw = copy.copy(kwargs)
        if indent is not None:
            nextkw['indent'] += 2
        parts = (encode_diagnostic(item, **nextkw) for item in obj)
        wsp_sep = '\n' if indent is not None else ' '
        mid = f',{wsp_sep}'.join(parts)
        text = f'[{wsp_sep}{mid}{wsp_sep}{wsp_indent}]'
    elif isinstance(obj, dict):
        nextkw = copy.copy(kwargs)
        if indent is not None:
            nextkw['indent'] += 2

        def encode_pair(key, val):
            enc_key = encode_diagnostic(key, **nextkw)
            enc_val = encode_diagnostic(val, **nextkw)
            if indent is not None:
                enc_val = enc_val[indent + 2:]
            return f'{enc_key}:{enc_val}'

        parts = (encode_pair(*pair) for pair in obj.items())
        wsp_sep = '\n' if indent is not None else ' '
        mid = f',{wsp_sep}'.join(parts)
        text = f'{{{wsp_sep}{mid}{wsp_sep}{wsp_indent}}}'
    elif isinstance(obj, six.integer_types) or hasattr(obj, '__int__'):
        text = str(int(obj))
    elif isinstance(obj, bool) or hasattr(obj, '__bool__'):
        text = 'true' if bool(obj) else 'false'
    elif isinstance(obj, six.binary_type) or hasattr(obj, '__bytes__'):
        enc = bytes(obj)
        bstr_as = kwargs.get('bstr_as', 'hex')
        if bstr_as == 'hex':
            text = "h'{}'".format(binascii.hexlify(enc).decode('utf8'))
        elif bstr_as == 'base64':
            text = "b64'{}'".format(binascii.b2a_base64(enc, newline=False).decode('utf8'))
        else:
            raise ValueError('Invalid bstr_as parameter')
    elif isinstance(obj, six.text_type):
        text = '"{}"'.format(obj)
    elif obj is None:
        text = 'null'
    else:
        raise TypeError('Unencodable value ({}): {}'.format(type(obj), repr(obj)))

    # prepend unconditionally
    if text and wsp_indent:
        text = wsp_indent + text
    return text
