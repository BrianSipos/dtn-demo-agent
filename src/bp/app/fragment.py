''' Application layer adaptors.
'''
import cbor2
from dataclasses import dataclass, field, fields
from gi.repository import GLib as glib
import logging
import portion
from typing import Optional, Tuple

from bp.encoding import (
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
)
from bp.util import BundleContainer, ChainStep
from bp.app.base import app, AbstractApplication

LOGGER = logging.getLogger(__name__)


@dataclass
class Reassembly(object):
    ''' State for fragmented bundles.
    '''

    #: The reassembled bundle ident
    ident: Tuple
    #: Total transfer size
    total_length: int
    #: The full first-fragment bundle
    first_frag: Optional[Bundle] = None
    # Range of full data expected
    total_valid: Optional[portion.Interval] = None
    #: Range of real data present
    valid: Optional[portion.Interval] = None
    #: Accumulated byte string
    data: Optional[bytearray] = None


@app('fragment')
class Fragment(AbstractApplication):
    ''' Bundle Protocol security.
    '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config = None
        # Key is the reassembled bundle ident
        self._reassembly = {}

    def load_config(self, config):
        self._config = config

    def add_chains(self, rx_chain, tx_chain):
        rx_chain.append(ChainStep(
            order=10,
            name='Fragment reassembly',
            action=self._reassemble
        ))
        tx_chain.append(ChainStep(
            order=20,
            name='Fragment creation',
            action=self._create
        ))

    def _create(self, ctr):
        if ctr.route is None:
            return
        mtu = ctr.route.mtu

        orig_size = len(ctr.bundle)
        bundle_flags = ctr.bundle.primary.bundle_flags
        should_fragment = (
            mtu is not None
            and orig_size > mtu
            and not bundle_flags & PrimaryBlock.Flag.NO_FRAGMENT
            and not bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT
        )
        LOGGER.info('Unfragmented size %d with MTU %s, should fragment %s', orig_size, mtu, should_fragment)

        if not should_fragment:
            # no fragmentation
            return

        # take the payload data to fragment it
        pyld_blk = ctr.block_num(Bundle.BLOCK_NUM_PAYLOAD)
        payload_data = pyld_blk.getfieldval('btsd')
        pyld_blk.delfieldval('btsd')
        payload_size = len(payload_data)
        LOGGER.info('Payload data size %d', payload_size)
        # maximum size of each fragment field
        pyld_size_enc = len(cbor2.dumps(payload_size))

        # two encoded sizes for fragment, one for payload bstr head
        non_pyld_size = orig_size - payload_size + 3 * pyld_size_enc
        LOGGER.info('Non-payload size %d', non_pyld_size)
        if non_pyld_size > mtu:
            raise RuntimeError('Non-payload size {} too large for route MTU {}'.format(orig_size, mtu))

        frag_offset = 0
        while frag_offset < len(payload_data):
            fctr = BundleContainer()
            fctr.bundle.primary = ctr.bundle.primary.copy()
            fctr.bundle.primary.bundle_flags |= PrimaryBlock.Flag.IS_FRAGMENT
            fctr.bundle.primary.fragment_offset = frag_offset
            fctr.bundle.primary.total_app_data_len = payload_size

            for blk in ctr.bundle.blocks:
                if (frag_offset == 0
                    or blk.block_flags & CanonicalBlock.Flag.REPLICATE_IN_FRAGMENT
                    or blk.block_num == Bundle.BLOCK_NUM_PAYLOAD):
                    fctr.bundle.blocks.append(blk.copy())
            # ensure full size (with zero-size payload)
            fctr.reload()
            fctr.bundle.fill_fields()

            non_pyld_size = len(fctr.bundle)
            # zero-length payload has one-octet encoded bstr head
            frag_size = mtu - (non_pyld_size - 1 + pyld_size_enc)
            if frag_size <= 0:
                raise RuntimeError('Payload size {} too large for route MTU {}'.format(frag_size, mtu))

            LOGGER.info('Fragment non-payload size %d, offset %d, (max) size %d', non_pyld_size, frag_offset, frag_size)
            frag_data = payload_data[frag_offset:(frag_offset + frag_size)]
            frag_offset += frag_size

            fctr.block_num(Bundle.BLOCK_NUM_PAYLOAD).setfieldval('btsd', frag_data)

            glib.idle_add(self._agent.send_bundle, fctr)

        # internal action, not delete
        ctr.route = None
        ctr.sender = None
        return True

    def _reassemble(self, ctr):
        if 'deliver' not in ctr.actions:
            return
        if not (ctr.bundle.primary.bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT):
            return

        final_ident = ctr.bundle_ident()[:3]
        frag_offset = ctr.bundle.primary.fragment_offset
        total_length = ctr.bundle.primary.total_app_data_len

        reassm = self._reassembly.get(final_ident, None)
        if reassm is None:
            reassm = Reassembly(
                ident=final_ident,
                total_length=total_length,
                total_valid=portion.closedopen(0, total_length),
                valid=portion.empty(),
                data=bytearray(total_length)
            )
            self._reassembly[final_ident] = reassm
        else:
            if reassm.total_length != total_length:
                LOGGER.warning('Mismatch in fragment-bundle total application data length')

        if frag_offset == 0:
            reassm.first_frag = ctr.bundle

        # Inject the new fragment
        payload_data = ctr.block_num(1).getfieldval('btsd')
        end_ix = frag_offset + len(payload_data)
        reassm.data[frag_offset:end_ix] = payload_data
        reassm.valid |= portion.closedopen(frag_offset, end_ix)

        if reassm.valid == reassm.total_valid:
            del self._reassembly[final_ident]
            LOGGER.info('Finished reassembly of %s size %d', final_ident, reassm.total_length)

            # Synthesize original bundle
            rctr = BundleContainer()
            rctr.bundle.primary = reassm.first_frag.primary.copy()
            rctr.bundle.primary.bundle_flags &= ~PrimaryBlock.Flag.IS_FRAGMENT
            rctr.bundle.primary.crc_type = AbstractBlock.CrcType.NONE
            rctr.bundle.primary.crc_value = None

            LOGGER.debug('Copying %d first-fragment blocks', len(reassm.first_frag.blocks))
            for blk in reassm.first_frag.blocks:
                rctr.bundle.blocks.append(blk.copy())
            rctr.reload()
            pyld_blk = rctr.block_num(Bundle.BLOCK_NUM_PAYLOAD)
            pyld_blk.setfieldval('btsd', reassm.data)
            pyld_blk.crc_type = AbstractBlock.CrcType.NONE
            pyld_blk.crc_value = None

            glib.idle_add(self._agent.recv_bundle, rctr)

        ctr.actions.clear()
        return True
