''' Conversion behavior for self-delimited numeric value (SDNV) type.
'''

import logging
import math


#: module-level logger
logger = logging.getLogger(__name__)

#: Bitmask for value portion of each octet
VAL_MASK = 0x7F
#: Bitmask for continuation bit of each octet
CNT_MASK = 0x80


def sdnvlen(val):
    ''' Get the encoded length required to fit an integer value.
    
    :param val: The integer to convert.
    :type val: int or similar
    :return: The length of encoded data required.
    :rtype: int
    '''
    if val < 0:
        raise ValueError('SDNV can only encode non-negative')
    elif val == 0:
        return 1

    return int(math.ceil(math.log(val) / math.log(128)))


def int2sdnv(val):
    ''' Convert from integer to SDNV-encoded data string.
    
    :param val: The integer to convert.
    :type val: int or similar
    :return: The encoded data.
    :rtype: str
    '''

    val = int(val)
    if val < 0:
        raise ValueError('Cannot SDNV-encode negative value')

    s = []
    s.insert(0, (val & VAL_MASK))  # LS word has end bit
    while True:
        val = val >> 7
        if val == 0:
            break
        s.insert(0, CNT_MASK | (val & VAL_MASK))
    return bytearray(s)


def sdnv2int(data):
    ''' Decode available SDNV data string.
    
    :param data: The full input data.
    :type data: bytes
    :return: A pair of values representing:
        1. The unprocessed non-SDNV tail.
        2. The processed integer.
    :rtype: tuple of (bytes, int)
    '''

    # ix value to index just-past last read digit
    ix = 0
    max_ix = len(data)
    val = 0
    while True:
        # Didn't exit and no more data
        if ix >= max_ix:
            logger.warning("Broken SDNV: no ending byte")
            break

        dit = int(bytearray([data[ix]])[0])
        ix += 1

        val = val << 7
        val += dit & VAL_MASK

        # Exit once continuation bit it zero
        if dit & CNT_MASK == 0:
            break

    return data[ix:], val
