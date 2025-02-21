# Replacement Cycling Attacks with Warnet
Checkout the [setup docs](docs/setup.md) for instructions on how to install Warnet and the dependencies required to run the scenarios in this repository.

## Replacement Cycling Attacks with Warnet Overview
The Warnet scenarios implemented in this repository demonstrate Replacement Cycling Attacks in a few different configurations. They are
motivated by Antoine Riard's work on demonstrating Replacement Cycling Attacks using Bitcoin Core's functional
test framework (BitcoinTestFramework). See more about Riard's original work in the [References](./docs/references.md).

There are some key differences between the Warnet scenarios and Riard's original work due to the architecture of Warnet. To begin, Warnet is built around a distributed architecture where the `Commander` runs in its own container/pod within a Kubernetes cluster, separate from the Bitcoin nodes (`Tanks`). The `Commander` communicates with the Tanks through RPC commands executed via `kubectl`, meaning that all node interactions occur over an RPC interface rather than through direct, in-process communication like the BitcoinTestFramework. This isolation prevents the `Commander` from accessing the same internal state as in the BitcoinTestFramework, which prevents, for example use of a MiniWallet in the same manner as the BitcoinTestFramework.

In the standard BitcoinTestFramework setup, the MiniWallet is "funded" by the pre-mined, mature coinbase transactions. So calling something like the following in a standard BitcoinTestFramework test will return a UTXO no worries, but not in Warnet.
```python
    self.wallet = MiniWallet(self.nodes[0])
    ...
    self.generate(self.nodes[0], 501)
    utxo = self.wallet.get_utxo()
```
Warnet error:
```python
    get_utxo = self.wallet.get_utxo()
               ^^^^^^^^^^^^^^^^^^^^^^
  File "/shared/archive.pyz/test_framework/wallet.py", line 229, in get_utxo
    index = self._utxos.index(next(utxo_filter))
                              ^^^^^^^^^^^^^^^^^
StopIteration
```

Concretely, in the BitcoinTestFramework, funding occurs automatically when the node mines enough blocks and the MiniWallet rescans the chain, populating its UTXO list. And while you can instantiate a MiniWallet within a Warnet scenario, the necessary live UTXO state isn’t available via RPC, so you'll get an error like the above.

### Replacement Cycling 1
> [!NOTE]
> This scenario is complete, though more tweaking and guidance around fee-rate configuration is needed.

The first scenario is motivated by [Riard's original work](https://github.com/ariard/bitcoin/commits/2023-test-mempool) (which is available for reference in this repository at [reference/riard_replacement_cycling_1.py](./reference/riard_replacement_cycling_1.py)). It is built around the same low-level mechanics, but is more configurable and perhaps easier to understand.

If comparing to Riard's work, please note the following equivalences:
- VICTIM: `Alice` (Riard) is equivalent to `Bob` (Warnet)
- ATTACKER: `Bob` (Riard) is equivalent to `Mallory` (Warnet)
- FUNDS: MiniWallet (Riard) functionality provided by `Alice` (Warnet)

This scenario does not use the Lightning Network capabilities of Warnet and simply demonstrates the mechanics of a Replacement Cycling Attack using only Bitcoin Core nodes and (manually created) Lightning Network-like primitives such as channels (2-of-2 multisigs) and HTLC and channel state transactions (such as commitment, timeout and pre-image transactions). More specifically:
- Channel openings are simulated using manually created 2-of-2 multisig transactions (as opposed to the interactive and automated channel opening process of Lightning Nodes).
- Channel closes are simulated using manually created transactions that are similar to commitment transactions.
- Manually created transactions are used for the timeout and pre-image transactions.
- The MiniWallet construct is not used as it is not possible to do so. The Warnet scenario is based on a network of 3 Bitcoin core nodes with 1 (`Alice`) acting as a miner only and not actively participating in the scenario other than to mine blocks and fund other nodes, and the remaining 2 nodes (`Mallory` and `Bob`) acting as active participants. In Riard's original work he uses just 2 nodes (`Alice` and `Bob`) as active participants and uses the MiniWallet construct for funding.

For full details of the scenario, including a step-by-step breakdown of the attack, see the [Replacement Cycling Scenario 1 documentation](./docs/replacement-cycling-1.md). The code for this scenario is implemented in [scenarios/replacement_cycling_1.py](./scenarios/replacement_cycling_1.py).

### Replacement Cycling 2
> [!WARNING]
> This scenario is a WIP and not yet available.

This second scenario moves away from the low-level mechanics demonstrating a recycling attack in the first scenario and utilises more of the capabilities of Warnet. Specifically, it leverages the ability to spin up Lightning Nodes and then interact with them in a manner similar to the RPC access to Bitcoin Core nodes.

For full details of the scenario, including a step-by-step breakdown of the attack, see the [Replacement Cycling Scenario 2 documentation](./docs/replacement-cycling-2.md). The code for this scenario is implemented in [scenarios/replacement_cycling_2.py](./scenarios/replacement_cycling_2.py).
