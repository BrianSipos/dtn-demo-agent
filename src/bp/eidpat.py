''' Implementation of EID Patterns <https://datatracker.ietf.org/doc/draft-ietf-dtn-eid-pattern/>
'''
from abc import abstractmethod, ABCMeta
import copy
from dataclasses import dataclass, field
from typing import Any, ClassVar, List, Optional, Tuple, Type, Union
import cbor2
import portion

Scheme = Union[str, int]
''' Possible values for the scheme part of a pattern item '''


@dataclass
class EidRepr:
    ''' Internal representation of an EID value '''
    scheme: Scheme
    ssp: Any


@dataclass
class PatternItem(metaclass=ABCMeta):
    ''' Each item of a pattern '''

    INDEX: ClassVar[int] = None
    ''' Registered encoded value '''
    NAME: ClassVar[str] = None
    ''' Registered URI scheme name '''

    scheme: Scheme
    ''' Scheme for this pattern item. '''
    altscheme: Optional[Scheme]
    ''' If known, the alternate form from :ivar:`scheme` for this item. '''

    def __repr__(self) -> str:
        return 'Item(' + str(self.scheme) + ':' + self.to_ssp_text() + ')'

    def scheme_match(self, val: Scheme) -> bool:
        ''' Determine if this item matches at least the scheme of an EID '''
        return (
            val == self.scheme
            or (
                self.altscheme is not None
                and val == self.altscheme
            )
        )

    def pref_scheme(self, cls) -> Optional[int]:
        ''' Get preferred scheme type, falling back to the main scheme '''
        if isinstance(self.scheme, cls):
            return self.scheme
        if isinstance(self.altscheme, cls):
            return self.altscheme
        return self.scheme

    @abstractmethod
    def is_match(self, eid: EidRepr) -> bool:
        ''' Determine if a specific EID matches this pattern. '''
        raise NotImplementedError

    @abstractmethod
    def from_ssp_text(self, ssp: str) -> None:
        ''' Input the SSP from text form '''
        raise NotImplementedError

    @abstractmethod
    def to_ssp_text(self) -> str:
        ''' Output the SSP to text form '''
        raise NotImplementedError

    @abstractmethod
    def from_ssp_cbor(self, ssp: object) -> None:
        ''' Input the SSP from encoded CBOR form '''
        raise NotImplementedError

    @abstractmethod
    def to_dec_cbor(self) -> object:
        ''' Output the SSP to encoded CBOR form '''
        raise NotImplementedError


class AnySspItem(PatternItem):
    ''' Special case for any-SSP item with no state '''

    TEXT_FORM = '**'

    def is_match(self, eid: EidRepr) -> bool:
        return self.scheme_match(eid.scheme)

    def from_ssp_text(self, ssp: str):
        if ssp != self.TEXT_FORM:
            raise ValueError

    def to_ssp_text(self) -> str:
        return self.TEXT_FORM

    def from_ssp_cbor(self, _ssp: object) -> None:
        return

    def to_dec_cbor(self) -> object:
        return self.pref_scheme(int)


class UnsignedElement:
    ''' The type of each element for the IPN scheme pattern '''

    def __init__(self):
        self.val: Union[None, True, int, portion.Interval] = None

    def __repr__(self):
        return repr(self.val)

    def is_match(self, elem: int) -> bool:
        if self.val is True:
            return True
        elif isinstance(self.val, portion.Interval):
            return elem in self.val
        else:
            return self.val == elem

    def from_text(self, part: str):
        if part == '*':
            self.val = True
        elif part[0] == '[':
            if part[-1] != ']':
                raise ValueError(f'Mismatched range bracket in: {part}')
            intvls = part[1:-1].split(',')

            self.val = portion.Interval()
            for intvl in intvls:
                if intvl[-1] == '+':
                    # case for non-finite representation
                    self.val |= portion.closedopen(int(intvl[:-1]), portion.inf)
                elif '-' in intvl:
                    low, high = intvl.split('-')
                    self.val |= portion.closed(int(low), int(high))
                else:
                    self.val |= portion.singleton(int(intvl))
        else:
            self.val = int(part)

    def to_text(self) -> str:
        if self.val is None:
            return ''
        elif self.val is True:
            return '*'
        elif isinstance(self.val, portion.Interval):
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

    def from_ssp_cbor(self, ssp: object) -> None:
        if isinstance(ssp, list):
            mut = copy.copy(ssp)

            self.val = portion.Interval()
            ref = None
            closed = True
            while mut:
                if self.val.empty:
                    # least value
                    ref = mut.pop(0)
                else:
                    # excluded width
                    width = mut.pop(0)
                    ref += width + 1

                if not mut:
                    closed = False
                    break

                # included width
                width = mut.pop(0)
                high = ref + width
                self.val |= portion.closed(int(ref), int(high))
                ref += width + 1

            if not closed:
                # last included width
                self.val |= portion.closedopen(int(ref), portion.inf)

        else:
            # either int or True
            self.val = ssp

    def to_dec_cbor(self) -> object:
        if isinstance(self.val, portion.Interval):
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

                if intvl.right is portion.CLOSED:
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


@dataclass
class IpnSchemeItem(PatternItem):
    ''' The IPN scheme with a numeric range for three elements'''
    INDEX: ClassVar[int] = 2
    NAME: ClassVar[str] = 'ipn'

    alloc: Optional[UnsignedElement] = field(default_factory=UnsignedElement)
    ''' The allocator pattern or None to indicate that :ivar:`node` is the 64-bit FQNN '''
    node: UnsignedElement = field(default_factory=UnsignedElement)
    ''' The unqualified node number or FQNN pattern '''
    serv: UnsignedElement = field(default_factory=UnsignedElement)
    ''' The service number pattern '''

    def is_match(self, eid: EidRepr) -> bool:
        if not self.scheme_match(eid.scheme):
            return False

        # normalize the EID value
        if len(eid.ssp) == 2:
            anum = eid.ssp[0] >> 32
            qnum = eid.ssp[0] & 0xFFFFFFFF
            snum = eid.ssp[1]
        elif len(eid.ssp) == 3:
            anum = eid.ssp[0]
            qnum = eid.ssp[1]
            snum = eid.ssp[2]
        else:
            raise ValueError

        if self.alloc is not None:
            return all([
                self.alloc.is_match(anum),
                self.node.is_match(qnum),
                self.serv.is_match(snum),
            ])
        else:
            fqnn = (anum << 32) + qnum
            return all([
                self.node.is_match(fqnn),
                self.serv.is_match(snum),
            ])

    def from_ssp_text(self, ssp: str):
        parts = ssp.split('.')
        if len(parts) == 2:
            self.alloc = None
            # split off the FQNN part
            self.node.from_text(parts[0])
            self.serv.from_text(parts[1])
        elif len(parts) == 3:
            self.alloc.from_text(parts[0])
            self.node.from_text(parts[1])
            self.serv.from_text(parts[2])
        else:
            raise ValueError('IPN SSP does not have 2 or 3 elements')

    def to_ssp_text(self) -> str:
        parts = []
        if self.alloc:
            parts.append(self.alloc.to_text())
        parts.append(self.node.to_text())
        parts.append(self.serv.to_text())
        return '.'.join(parts)

    def from_ssp_cbor(self, ssp: object) -> None:
        if len(ssp) == 2:
            self.alloc = None
            # split off the FQNN part
            self.node.from_ssp_cbor(ssp[0])
            self.serv.from_ssp_cbor(ssp[1])
        elif len(ssp) == 3:
            self.alloc.from_ssp_cbor(ssp[0])
            self.node.from_ssp_cbor(ssp[1])
            self.serv.from_ssp_cbor(ssp[2])
        else:
            raise ValueError('IPN SSP does not have 2 or 3 elements')

    def to_dec_cbor(self) -> object:
        parts = []
        if self.alloc:
            parts.append(self.alloc.to_dec_cbor())
        parts.append(self.node.to_dec_cbor())
        parts.append(self.serv.to_dec_cbor())

        return [self.pref_scheme(int), parts]


_KNOWN_SCHEMES = {IpnSchemeItem}
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
    items: Optional[List[PatternItem]] = field(default_factory=list)
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

    def _use_scheme(self, scheme: Scheme) -> Tuple[Type[PatternItem], Optional[Scheme]]:
        cls = None
        altscheme = None
        if isinstance(scheme, int):
            try:
                cls = _KNOWN_SCHEMES_INDEX[scheme]
                altscheme = cls.NAME
            except KeyError:
                pass
        elif isinstance(scheme, str):
            # leave as text
            try:
                cls = _KNOWN_SCHEMES_NAME[scheme]
                altscheme = cls.INDEX
            except KeyError:
                pass
        else:
            raise TypeError

        return cls, altscheme

    def from_text(self, text: str) -> 'EidPattern':
        ''' Decode text into an EID Pattern. '''
        text = text.strip()
        if text == '*:**':
            self.items = None
        elif text == '':
            self.items = []
        else:
            self.items = []
            for part in text.split('|'):
                part = part.strip()
                try:
                    scheme, ssp = part.split(':', 2)
                except ValueError:
                    raise ValueError(f'Pattern item does not contain a separator colon: {part}')

                scheme = scheme.casefold()
                try:
                    scheme = int(scheme)
                except ValueError:
                    # leave as text
                    pass
                cls, altscheme = self._use_scheme(scheme)
                # override for any-SSP independent of scheme
                # after altscheme is determined
                if ssp == AnySspItem.TEXT_FORM:
                    cls = AnySspItem

                if cls is None:
                    raise UnknownSchemeError(f'Unknown scheme {scheme}')

                kwargs = dict(scheme=scheme, altscheme=altscheme)
                item = cls(**kwargs)
                item.from_ssp_text(ssp)
                self.items.append(item)

        return self

    def to_text(self) -> str:
        if self.items is None:
            return '*:**'
        else:
            accum = []
            for item in self.items:
                accum.append(str(item.pref_scheme(str)) + ':' + item.to_ssp_text())
            return '|'.join(accum)

    def from_cbor(self, data: bytes) -> 'EidPattern':
        obj = cbor2.loads(data)
        if obj is True:
            self.items = None
        else:
            self.items = []
            for part in obj:
                if isinstance(part, list):
                    # pair of scheme and SSP pattern
                    scheme, ssp = part
                    cls, altscheme = self._use_scheme(scheme)
                else:
                    # any-ssp with just scheme
                    scheme, ssp = part, None
                    _cls, altscheme = self._use_scheme(scheme)
                    cls = AnySspItem

                kwargs = dict(scheme=scheme, altscheme=altscheme)
                item = cls(**kwargs)
                item.from_ssp_cbor(ssp)
                self.items.append(item)

        return self

    def to_cbor(self) -> bytes:
        if self.items is None:
            obj = True
        else:
            obj = []
            for item in self.items:
                obj.append(item.to_dec_cbor())

        return cbor2.dumps(obj)
