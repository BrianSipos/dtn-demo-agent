''' Utility helpers.
'''
from dataclasses import dataclass, field, fields
import datetime
import functools
from typing import Dict, Optional, Callable
import logging
from bp.config import TxRouteItem
from bp.encoding import (
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
    AdminRecord,
    StatusReport, StatusInfoArray, StatusInfo
)

LOGGER = logging.getLogger(__name__)


class BundleContainer(object):
    ''' A high-level representation of a bundle.
    This includes logical constraints not present in :py:cls:`encoding.Bundle`
    data handling class.

    :ivar bundle: The decoded bundle itself.
    :ivar actions: Processing recorded on this bundle.
    :ivar status_reason: The last status reason.
    :ivar route: The transmit route (type :py:cls:`TxRouteItem`) chosen for this bundle.
    :ivar sender: The transmit function to send this bundle.
    '''

    def __init__(self, bundle=None):
        if bundle is None:
            bundle = Bundle()
        self.bundle = bundle
        # Block number generator
        self._last_block_num: int = 1
        # Map from block number to single Block
        self._block_num: Dict[int, CanonicalBlock] = {}
        # Map from block type to list of Blocks
        self._block_type: Dict[int, CanonicalBlock] = {}
        # History of actions
        self.actions: Dict[str, datetime.datetime] = {}
        # Last status reason
        self.status_reason: int = None

        self.route: TxRouteItem = None
        self.sender: Callable = None

        self.reload()

    def __repr__(self, *_args, **_kwargs):
        return self.bundle.show(dump=True)

    def block_num(self, num):
        ''' Look up a block by unique number.

        :param num: The block number to look up.
        :return: The block with that number.
        :raise KeyError: If the number is not present.
        '''
        return self._block_num[num]

    def block_type(self, type_code):
        ''' Look up a block by type code or data class.

        :param type_code: The type code to look up.
        :return: A list of blocks of that type, which may be empty.
        '''
        return self._block_type.get(type_code, [])

    def log_name(self):
        ''' Get a log-friendly name for this bundle.
        '''
        return '(dest {}, ident {})'.format(
            self.bundle.primary.destination,
            self.bundle_ident()
        )

    def bundle_ident(self):
        ''' Get the bundle identity (source + timestamp) as a tuple.
        '''
        pri = self.bundle.getfieldval('primary')
        ident = [
            pri.source,
            pri.create_ts.getfieldval('dtntime'),
            pri.create_ts.getfieldval('seqno')
        ]
        if pri.bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT:
            ident += [
                pri.fragment_offset,
                pri.total_app_data_len,
            ]
        return tuple(ident)

    def _block_types(self, key):
        ''' Get or create a block-type array.
        '''
        if key not in self._block_type:
            self._block_type[key] = []
        return self._block_type[key]

    def add_block(self, blk):
        ''' Add an extension block.
        The block is added just before the payload.
        :param blk: The existing block to remove (and reindex).
        This block will have its BTSD set if not already.
        '''
        if not isinstance(blk, CanonicalBlock):
            raise TypeError()

        blk_type = blk.getfieldval('type_code')
        blk_num = self._fix_blk_num(blk)
        pyld_cls = type(blk.payload)
        if blk_num in self._block_num:
            raise KeyError('add_block() given duplicate block number {}'.foramt(blk_num))

        blk.ensure_block_type_specific_data()

        self.bundle.blocks.insert(-1, blk)
        self._block_num[blk_num] = blk
        self._block_types(blk_type).append(blk)
        self._block_types(pyld_cls).append(blk)

    def remove_block(self, blk):
        ''' Remove an extension block.
        :param blk: The existing block to remove (and reindex).
        '''
        if not isinstance(blk, CanonicalBlock):
            raise TypeError()

        blk_num = blk.getfieldval('block_num')
        blk_type = blk.getfieldval('type_code')
        pyld_cls = type(blk.payload)

        found = [
            (ix, curblk)
            for (ix, curblk) in enumerate(self.bundle.blocks)
            if curblk.block_num == blk_num
        ]

        if found:
            (ix, curblk) = found[0]
            self.bundle.blocks.pop(ix)
            self._block_num.pop(blk_num)
            self._block_type[blk_type].remove(curblk)
            self._block_type[pyld_cls].remove(curblk)

    def reload(self):
        ''' Reload derived info from the bundle.
        '''
        if self.bundle is None:
            return

        try:
            self._block_num = {}
            self._block_type = {}
            if self.bundle.payload is not None:
                self._block_num[0] = self.bundle.payload
            for blk in self.bundle.getfieldval('blocks'):
                blk.ensure_block_type_specific_data()

                blk_num = blk.getfieldval('block_num')
                if blk_num is not None:
                    if blk_num in self._block_num:
                        raise RuntimeError('Duplicate block_num value {}'.format(blk_num))
                    self._block_num[blk_num] = blk

                blk_type = blk.getfieldval('type_code')
                pyld_cls = type(blk.payload)
                for key in (blk_type, pyld_cls):
                    self._block_types(key).append(blk)
        except:
            self._block_num = {}
            self._block_type = {}
            raise

    def get_block_num(self):
        ''' Get the next unused block number.
        :return: An unused number.
        '''
        while True:
            self._last_block_num += 1
            if self._last_block_num not in self._block_num:
                return self._last_block_num

    def fix_block_num(self):
        ''' Assign unique block numbers where needed.
        '''
        for blk in self.bundle.getfieldval('blocks'):
            self._fix_blk_num(blk)

    def _fix_blk_num(self, blk):
        blk_num = blk.getfieldval('block_num')
        if blk_num is None:
            if blk.getfieldval('type_code') == Bundle.BLOCK_TYPE_PAYLOAD:
                blk_num = Bundle.BLOCK_NUM_PAYLOAD
            else:
                blk_num = self.get_block_num()
            blk.overloaded_fields['block_num'] = blk_num
        return blk_num

    def record_action(self, action: str, reason: Optional[int]=None):
        ''' Mark an action on this bundle.
        '''
        self.actions[action] = datetime.datetime.now(datetime.timezone.utc)
        if reason is not None:
            # supersede any earlier reason
            self.status_reason = reason

    def create_report(self):
        # Request for each action status
        FLAGS = {
            'delete': PrimaryBlock.Flag.REQ_DELETION_REPORT,
            'deliver': PrimaryBlock.Flag.REQ_DELIVERY_REPORT,
            'forward': PrimaryBlock.Flag.REQ_FORWARDING_REPORT,
            'receive': PrimaryBlock.Flag.REQ_RECEPTION_REPORT,
        }
        # Field name of the StatusInfoArray
        STATUS_FIELD = {
            'delete': 'deleted',
            'deliver': 'delivered',
            'forward': 'forwarded',
            'receive': 'received',
        }

        status_dest = self.bundle.primary.report_to
        if status_dest is None or status_dest == 'dtn:none':
            return None

        own_flags = self.bundle.primary.getfieldval('bundle_flags')
        status_ts = bool(own_flags & PrimaryBlock.Flag.REQ_STATUS_TIME)

        status_array = StatusInfoArray()
        any_status = False
        for (action, timestamp) in self.actions.items():
            try:
                flag = FLAGS[action]
            except KeyError:
                continue
            if not (own_flags & flag):
                continue

            status_info = StatusInfo(
                status=True,
                at=(timestamp if status_ts else None),
            )
            status_array.setfieldval(STATUS_FIELD[action], status_info)
            any_status = True

        if not any_status:
            return None

        report = StatusReport(
            status=status_array,
            reason_code=(self.status_reason if self.status_reason else StatusReport.ReasonCode.NO_INFO),
            subj_source=self.bundle.primary.source,
            subj_ts=self.bundle.primary.create_ts,
        )

        reply = BundleContainer()
        reply.bundle.primary = PrimaryBlock(
            bundle_flags=PrimaryBlock.Flag.PAYLOAD_ADMIN,
            destination=self.bundle.primary.report_to,
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        reply.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=AbstractBlock.CrcType.CRC32,
            ) / AdminRecord(
            ) / report,
        ]
        return reply


@dataclass
@functools.total_ordering
class ChainStep():
    # Absolute ordering of steps
    order: float = 0
    # Human name of the step
    name: str = 'unknown'
    # Action to perform on the bundle at this step.
    # Returns True if the processing chain is interrupted by this step.
    action: Callable[[BundleContainer], bool] = None

    def __lt__(self, other):
        return self.order < other.order
