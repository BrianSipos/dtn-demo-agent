''' Implementation of EID Patterns <https://datatracker.ietf.org/doc/draft-ietf-dtn-eid-pattern/>
'''
from abc import abstractmethod, ABCMeta
import copy
from dataclasses import dataclass, field
from typing import (
    Any, ClassVar, Dict, List, Literal, Optional, Set, Type, Union,
    cast
)
import cbor2
import portion


Scheme = Union[str, int]
''' Possible values for the scheme part of a pattern item '''


def norm_scheme(val: Scheme) -> Scheme:
    ''' Normalize an input scheme '''
    try:
        # prefer integer form
        scheme = int(val)
    except ValueError:
        if isinstance(val, str):
            # leave as text
            scheme = val.casefold()
        else:
            raise TypeError
    return scheme


@dataclass
class EidRepr:
    ''' Internal representation of an EID value '''
    scheme: Scheme
    ssp: Any


@dataclass
class PatternItem(metaclass=ABCMeta):
    ''' Each item of a pattern '''

    def __repr__(self) -> str:
        return 'Item(' + self.to_text() + ')'

    @abstractmethod
    def is_match(self, eid: EidRepr) -> bool:
        ''' Determine if a specific EID matches this pattern. '''
        raise NotImplementedError

    @abstractmethod
    def from_text(self, scheme: Scheme, ssp: str) -> None:
        ''' Input the SSP from text form.

        :param scheme: The part before the first colon.
        :param ssp: The part after the colon.
        '''
        raise NotImplementedError

    @abstractmethod
    def to_text(self) -> str:
        ''' Output the SSP to text form '''
        raise NotImplementedError

    @abstractmethod
    def from_dec_cbor(self, item: List[object]) -> None:
        ''' Input the item from decoded CBOR array form '''
        raise NotImplementedError

    @abstractmethod
    def to_dec_cbor(self) -> List[object]:
        ''' Output the SSP to decoded CBOR array form '''
        raise NotImplementedError


class SchemeSpecificItem(PatternItem):
    ''' A scheme-specific pattern definition '''

    INDEX: ClassVar[int]
    ''' Registered encoded value '''
    NAME: ClassVar[str]
    ''' Registered URI scheme name '''


@dataclass
class AnySspItem(PatternItem):
    ''' Special case for any-SSP item with no state '''

    TEXT_FORM: ClassVar[str] = '**'
    ''' The scheme-specific part '''

    ANYSCHEME = '*'
    ''' The wildcard match-all scheme '''

    schemes: Dict[Scheme, bool] = field(default_factory=list)
    ''' All schemes that this item applies to.
    The mapped values are False for unknown schemes and True for known.
    '''

    def is_match(self, eid: EidRepr) -> bool:
        if AnySspItem.ANYSCHEME in self.schemes:
            return True

        # Both forms are already normalized
        return eid.scheme in self.schemes

    def from_text(self, scheme: Scheme, ssp: str):
        if ssp != self.TEXT_FORM:
            raise ValueError

        if isinstance(scheme, str) and scheme.startswith('['):
            if scheme[-1] != ']':
                raise ValueError(f'Mismatched range bracket in: {scheme}')
            parts = scheme[1:-1].split(',')
        else:
            parts = [scheme]

        self.schemes = {
            norm_scheme(part): False for part in parts
        }

    def to_text(self) -> str:
        # prefer text form when known
        parts = [
            str(scheme)
            for scheme, known in self.schemes.items()
            if isinstance(scheme, str) or not known
        ]

        if len(parts) != 1:
            scheme = '[' + ','.join(parts) + ']'
        else:
            scheme = parts[0]

        return scheme + ':' + self.TEXT_FORM

    def from_dec_cbor(self, item: List[object]) -> None:
        if item[0] is not None:
            raise ValueError

        self.schemes = {
            norm_scheme(part): False for part in item[1:]
            if isinstance(part, (int, str))
        }

    def to_dec_cbor(self) -> List[object]:
        # prefer int form when known
        items = [
            scheme
            for scheme, known in self.schemes.items()
            if isinstance(scheme, int) or not known
        ]
        return [None] + items


class IntInterval(portion.AbstractDiscreteInterval):
    ''' An integer-domain interval class '''
    _step = 1


apiIntInterval = portion.create_api(IntInterval)
''' Utility functions for :py:cls:`IntInterval` '''


@dataclass
class UnsignedElement:
    ''' The type of each element for the IPN scheme pattern '''

    domain_max: Optional[int] = None
    ''' Maximum value within the element domain '''
    val: Union[None, Literal[True], int, IntInterval] = None
    ''' The element pattern form: wildcard True, single value int, range IntInterval '''

    def __repr__(self):
        return repr(self.val)

    def is_match(self, elem: int) -> bool:
        if self.val is True:
            return True
        elif isinstance(self.val, IntInterval):
            return elem in self.val
        else:
            return self.val == elem

    def from_value(self, val: int):
        if self.domain_max is not None and val > self.domain_max:
            raise ValueError('Value too large')
        self.val = val

    def from_text(self, part: str):
        if part == '*':
            self.val = True
        elif part[0] == '[':
            if part[-1] != ']':
                raise ValueError(f'Mismatched range bracket in: {part}')
            intvls = part[1:-1].split(',')

            self.val = IntInterval()
            for intvl in intvls:
                if not intvl:
                    raise ValueError('Empty range is invalid')
                if intvl[-1] == '+':
                    # case for non-finite representation
                    self.val |= apiIntInterval.closedopen(int(intvl[:-1]), portion.inf)
                elif '-' in intvl:
                    low, high = map(int, intvl.split('-'))
                    # swap to satisfy parsing requirement
                    if low > high:
                        low, high = high, low

                    if self.domain_max is None or high < self.domain_max:
                        self.val |= apiIntInterval.closed(low, high)
                    else:
                        self.val |= apiIntInterval.closedopen(low, portion.inf)
                else:
                    self.val |= portion.singleton(int(intvl))
        else:
            self.from_value(int(part))

    def to_text(self) -> str:
        if self.val is None:
            return ''
        elif self.val is True:
            return '*'
        elif isinstance(self.val, IntInterval):
            parts = []
            for intvl in self.val:
                if intvl.lower == intvl.upper:
                    parts.append(str(intvl.lower))
                elif intvl.upper == portion.inf:
                    parts.append(str(intvl.lower) + '+')
                else:
                    parts.append(str(intvl.lower) + '-' + str(intvl.upper))
            return '[' + ','.join(parts) + ']'
        else:
            return str(self.val)

    def from_dec_cbor(self, enc: object) -> None:
        if enc is True:
            self.val = True
        elif isinstance(enc, list):
            if not all(isinstance(item, int) for item in enc):
                raise ValueError('Range is not all integers')
            mut = copy.copy(enc)

            self.val = IntInterval()
            ref: Optional[int] = None
            closed = True
            while mut:
                if ref is None:
                    # least value
                    ref = cast(int, mut.pop(0))
                else:
                    # excluded width
                    width = cast(int, mut.pop(0))
                    ref += width + 1

                if not mut:
                    closed = False
                    break

                # included width
                width = cast(int, mut.pop(0))
                high = ref + width
                if self.domain_max is None or high < self.domain_max:
                    self.val |= apiIntInterval.closed(ref, high)
                else:
                    self.val |= apiIntInterval.closedopen(ref, portion.inf)
                ref += width + 1

            if not closed:
                # last included width
                self.val |= apiIntInterval.closedopen(ref, portion.inf)

        elif isinstance(enc, int):
            # either int or True
            self.from_value(enc)
        else:
            raise ValueError(f'Invalid value {enc}')

    def to_dec_cbor(self) -> object:
        if isinstance(self.val, IntInterval):
            ref = None
            parts = []
            for intvl in self.val:
                if not parts:
                    # least value
                    parts.append(intvl.lower)
                else:
                    # excluded width
                    width = (intvl.lower - 1) - ref
                    parts.append(width)
                ref = intvl.lower

                if intvl.right is apiIntInterval.CLOSED:
                    # finite
                    width = intvl.upper - ref
                    parts.append(width)
                    ref = intvl.upper + 1
                else:
                    # omitted infinite width
                    pass

            return parts
        else:
            # either int or True
            return self.val


UINT32_MAX = int(2**32) - 1
UINT64_MAX = int(2**64) - 1


@dataclass
class IpnSchemeItem(SchemeSpecificItem):
    ''' The IPN scheme with a numeric range for three elements'''
    INDEX: ClassVar[int] = 2
    NAME: ClassVar[str] = 'ipn'

    alloc: UnsignedElement = field(default_factory=lambda: UnsignedElement(domain_max=UINT32_MAX))
    ''' The allocator number pattern '''
    node: UnsignedElement = field(default_factory=lambda: UnsignedElement(domain_max=UINT32_MAX))
    ''' The unqualified node number pattern '''
    serv: UnsignedElement = field(default_factory=lambda: UnsignedElement(domain_max=UINT64_MAX))
    ''' The service number pattern '''

    def is_match(self, eid: EidRepr) -> bool:
        if eid.scheme not in {self.INDEX, self.NAME}:
            return False

        # normalize the EID value
        if len(eid.ssp) == 2:
            anum = eid.ssp[0] >> 32
            qnum = eid.ssp[0] & UINT32_MAX
            snum = eid.ssp[1]
        elif len(eid.ssp) == 3:
            anum = eid.ssp[0]
            qnum = eid.ssp[1]
            snum = eid.ssp[2]
        else:
            raise ValueError

        return all([
            self.alloc.is_match(anum),
            self.node.is_match(qnum),
            self.serv.is_match(snum),
        ])

    def from_text(self, scheme: Scheme, ssp: str):
        parts = ssp.split('.')
        if len(parts) == 2:
            # Special handling of single values
            if parts[0] == '!':
                fqnn = UINT32_MAX
            else:
                fqnn = int(parts[0])
            snum = int(parts[1])
            self.alloc.from_value(fqnn >> 32)
            self.node.from_value(fqnn & UINT32_MAX)
            self.serv.from_value(snum)
        elif len(parts) == 3:
            self.alloc.from_text(parts[0])
            self.node.from_text(parts[1])
            self.serv.from_text(parts[2])
        else:
            raise ValueError('IPN SSP does not have 3 elements')

    def to_text(self) -> str:
        parts = [
            self.alloc.to_text(),
            self.node.to_text(),
            self.serv.to_text(),
        ]
        return self.NAME + ':' + '.'.join(parts)

    def from_dec_cbor(self, item: List[object]) -> None:
        _scheme, ssp = item
        if not isinstance(ssp, list):
            raise ValueError('IPN SSP is not an array')

        if len(ssp) == 3:
            self.alloc = UnsignedElement(domain_max=UINT32_MAX)
            self.alloc.from_dec_cbor(ssp[0])
            self.node.domain_max = UINT32_MAX
            self.node.from_dec_cbor(ssp[1])
            self.serv.domain_max = UINT64_MAX
            self.serv.from_dec_cbor(ssp[2])
        else:
            raise ValueError('IPN SSP does not have 3 elements')

    def to_dec_cbor(self) -> List[object]:
        parts = []
        if self.alloc:
            parts.append(self.alloc.to_dec_cbor())
        parts.append(self.node.to_dec_cbor())
        parts.append(self.serv.to_dec_cbor())

        return [self.INDEX, parts]


_KNOWN_SCHEMES: Set[Type[SchemeSpecificItem]] = {IpnSchemeItem}
''' Registered scheme-specific items '''
_KNOWN_SCHEMES_INDEX = {cls.INDEX: cls for cls in _KNOWN_SCHEMES}
''' Lookup by index number '''
_KNOWN_SCHEMES_NAME = {cls.NAME.casefold(): cls for cls in _KNOWN_SCHEMES}
''' Lookup by lower case name '''


class UnknownSchemeError(ValueError):
    ''' Exception whhen scheme is not known but needed '''


@dataclass
class EidPattern:
    ''' Top container for EID Pattern data model '''
    items: List[PatternItem] = field(default_factory=list)
    ''' Either a list of items in the pattern or the None value to
    indicate the any-scheme pattern. '''

    def is_match(self, eid: EidRepr) -> bool:
        ''' Determine if a specific EID matches this pattern. '''
        if self.items is None:
            return True
        else:
            for item in self.items:
                if item.is_match(eid):
                    return True
            return False

    def _get_cls(self, scheme: Scheme) -> Optional[Type[SchemeSpecificItem]]:
        cls = None
        if isinstance(scheme, int):
            try:
                cls = _KNOWN_SCHEMES_INDEX[scheme]
            except KeyError:
                pass
        elif isinstance(scheme, str):
            # leave as text
            try:
                cls = _KNOWN_SCHEMES_NAME[scheme]
            except KeyError:
                pass

        return cls

    def normalize(self):
        ''' Normalize the entire pattern.
        This will modify its state.
        '''
        # coalesce down to single instance of this class
        seen_anyssp = [
            item for item in self.items
            if isinstance(item, AnySspItem)
        ]

        keep_anyssp = None
        if seen_anyssp:
            keep_anyssp = seen_anyssp.pop(0)
            for item in seen_anyssp:
                self.items.remove(item)
                # combine scheme keys, values get overwritten below
                keep_anyssp.schemes |= item.schemes

        if keep_anyssp:
            keep_others = []
            if AnySspItem.ANYSCHEME in keep_anyssp.schemes:
                # remove all other schemes and items
                keep_anyssp.schemes = {AnySspItem.ANYSCHEME: False}
            else:
                # expand 'known' scheme marking on remaining one
                new_schemes = {}
                for scheme in keep_anyssp.schemes.keys():
                    cls = self._get_cls(scheme)
                    if cls is None:
                        new_schemes[scheme] = False
                    else:
                        new_schemes[cls.INDEX] = True
                        new_schemes[cls.NAME] = True

                keep_anyssp.schemes = new_schemes

                # Remove redundant items of the same scheme
                keep_others = [
                    item for item in self.items
                    if isinstance(item, SchemeSpecificItem)
                    and not (
                        item.INDEX in keep_anyssp.schemes or item.NAME in keep_anyssp.schemes
                    )
                ]

            # move to front
            self.items = [keep_anyssp] + keep_others

    def from_text(self, text: str) -> 'EidPattern':
        ''' Decode text into an EID Pattern. '''
        text = text.strip()
        if text == '':
            self.items = []
        else:
            self.items = []
            for part in text.split('|'):
                part = part.strip()
                try:
                    scheme, ssp = part.split(':', 2)
                except ValueError:
                    raise ValueError(f'Pattern item does not contain a separator colon: {part}')

                # override for any-SSP independent of scheme
                if ssp == AnySspItem.TEXT_FORM:
                    cls = AnySspItem
                else:
                    scheme = norm_scheme(scheme)
                    cls = self._get_cls(scheme)

                if cls is None:
                    raise UnknownSchemeError(f'Unknown scheme {scheme}')

                item = cls()
                item.from_text(scheme, ssp)
                self.items.append(item)

        self.normalize()
        return self

    def to_text(self) -> str:
        accum = []
        for item in self.items:
            accum.append(item.to_text())
        return '|'.join(accum)

    def from_cbor(self, data: bytes) -> 'EidPattern':
        try:
            obj = cbor2.loads(data)
        except cbor2.CBORDecodeError:
            raise ValueError('Not well formed CBOR')

        if obj is True:
            self.items = [AnySspItem(schemes={AnySspItem.ANYSCHEME: False})]
        else:
            self.items = []
            for item_part in obj:
                if item_part[0] is None:
                    # any-ssp with list of schemes
                    cls = AnySspItem
                else:
                    # pair of scheme and SSP pattern
                    scheme = item_part[0]
                    cls = self._get_cls(scheme)

                if cls is None:
                    raise UnknownSchemeError(f'Unknown scheme {scheme}')

                item = cls()
                item.from_dec_cbor(item_part)
                self.items.append(item)

        self.normalize()
        return self

    def to_cbor(self) -> bytes:
        has_anyscheme = [
            item for item in self.items
            if isinstance(item, AnySspItem) and AnySspItem.ANYSCHEME in item.schemes
        ]
        if has_anyscheme:
            # structure special case
            obj = True
        else:
            obj = []
            for item in self.items:
                obj.append(item.to_dec_cbor())

        return cbor2.dumps(obj)
