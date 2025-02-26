# Replacement Cycling Scenario 1

This scenario is informed by Antoine Riard's basic demonstration of a [Replacement Cycling Attack](https://github.com/ariard/bitcoin/commits/2023-test-mempool). In this scenario we have 2 active participants in `Bob` and `Mallory`: `Bob` is the innocent party and intended victim and `Mallory` is the attacker.

`Bob` funds a channel with `Mallory`, locking up ~50 BTC. `Mallory`'s goal is to execute a Replacement Cycling Attack to steal `Bob`'s funds by:
1) Initially withholding the pre-image for the HTLC from `Bob`, forcing him to broadcast his commitment transaction,
2) Broadcasting a replacement chain of transactions, and doing so repeatedly with incremental but bumped fee rates, effectively out-bidding `Bob`'s timeout transaction (as her pre-image transaction has the `parent` transaction of her replacement chain as an input/parent)
3) Finally, broadcasting her pre-image transaction which (for her) hopefully leads to `Bob`'s timeout transaction being evicted from "the mempool", allowing her to claim the funds on offer in the output of the commitment transaction.

There's a third node in the setup, `Alice`, who both initially funds `Bob` and `Mallory` and also fulfils the role of miner.

## Running the scenario
The scenario can be run once Warnet is correctly installed and configured as per the [Setup](./setup.md) guide. The easiest way to run the scenario would be to use the `rc1` or `cycle1` targets in the [Makefile](../Makefile):
```bash
make rc1
# or
make cycle1
```
The `rc1` target will deploy a 3-node Bitcoin Core network and then run the scenario. To do these 2 stages manually (assuming the working directory is the project root):
```bash
warnet deploy networks/3_node_core
warnet run scenarios/replacement_cycling_1.py --debug
```
If you wish to run the scenario repeatedly (e.g. to test the impact of different parameters after making parameter changes), you should use the `cycle1` target in the [Makefile](../Makefile):
```bash
make cycle1
```
This will bring down any existing network, re-deploy a new 3-node Bitcoin Core network and then run the scenario.

## Configuring the scenario
The scenario, implemented in [scenarios/replacement_cycling_1.py](./scenarios/replacement_cycling_1.py), can be configured via the following parameters:
- `--replacement-rounds`: The number of replacement rounds to execute before the final stage of the attack, the broadcast of `Mallory`'s "winning" pre-image transaction.
- `--base_fee`: The initial/base fee rate (`sats/vbyte`) to use for the replacement rounds.
- `--fee_increment`: The fee rate increment (`sats/vbyte`) to apply each replacement round.

Due to a number of factors including absolute and relative transaction sizes, replacement policies, relay policies etc, however,there is only a narrow range of parameters that will result in a successful attack *when a constant `fee_increment` (as offered by this scenario) is used each replacement round*.

For example, if it is assumed that the `parent` and `child` transactions in the replacement chain are 122 and 96 vbytes in size respectively (as can be seem in the scenario's debug logs using the default configuration), then it's not possible to have more than 3 rounds using any (constant) `fee_increment` value!

### Replacement Cycling Attack Failures
Experimenting with the configuration parameters above will inevitably lead to the Replacement Cycling Attack failing, that is, `Mallory` is not successful in eliminating `Bob`'s timeout transaction from the mempool, with `Bob`'s timeout transaction eventually confirming. The following failure modes can be observed:
- "insufficient fee, rejecting replacement \<txid\>, not enough additional fees to relay"
- "insufficient fee, rejecting replacement \<txid\>, less fees than conflicting txs"
- "insufficient fee, rejecting replacement \<txid\>; new feerate \<X\> BTC/kvB <= old feerate \<Y\> BTC/kvB"
- "min relay fee not met"

## Scenario breakdown

### 0 - Setup: network, keys & wallets, funding and mining
The scenario starts by waiting for the network and nodes to reach a steady state. Private and public key pairs are created for the 2 active participants `Bob` and `Mallory`, `Alice` is configured as the miner (a wallet and an address for mining rewards is created) and then 298 blocks are mined by `Alice`.

Wallets are created for both `Bob` and `Mallory` and ~50 BTC is sent each:
- `Bob`'s ~50 BTC will be used to fund the channel with `Mallory`
- `Mallory`'s ~50 BTC will be used in her replacement chain

```
ReplacementCycling1 Setting up Mallory wallet...
ReplacementCycling1 Setting up Bob wallet...
ReplacementCycling1 Funding Mallory and Bob's wallets...
ReplacementCycling1 Mining 1 blocks...
ReplacementCycling1 Mined 1 blocks, new block height: 299
ReplacementCycling1 Mallory's balance: 49.99998000 BTC
ReplacementCycling1 Bob's balance: 49.99998000 BTC
```

```
Block height: 299
```

### 1 - Open channel
`Bob` "funds a channel" with `Mallory` by creating a 2-of-2 multisig and spending his ~50 BTC to it. A block is mined and the channel is "open".

```
Block height: 300
```

### 2 - Construct `Bob`'s commitment and timeout transactions
`Bob` constructs his commitment transaction and then his timeout transaction.

In the commitment transaction there are 2 possible spending conditions of the output:
1. Provide signatures from both `Bob` and `Mallory` - 2-of-2 multisig path
2. Provide the pre-image and signature from `Mallory`

`Bob`'s commitment transaction is a bit different from a standard commitment transaction that might be used in the real world in that it does not include a HTLC expiry so is intended to be broadcast as if the HTLC has already expired.

`Bob`'s timeout transaction is the refund transaction that will allow `Bob` to claim
the funds locked in the channel once the `timelock` period has passed. This transaction also feature use of `nSequence` to allow for RBF (with an initial sequence number of `0x1`).

```
Block height: 300
```

### 3 - Broadcast `Bob`'s commitment transaction
We've now moved beyond the preliminary setup stages and onto the core of the scenario.
We assume that `Mallory` has decided to withhold the pre-image for the HTLC from `Bob`. `Bob` decides to broadcast his commitment transaction to the network. We're doing this just 1 block after the channel was opened in this scenario for simplicity. In reality this would be some time after the channel was opened and the HTLC `cltv_expiry` has passed. As above this means that the commitment transaction does not include a HTLC expiry in its construction, it's intended to be broadcast as if the HTLC expiry has already passed.

Now `Bob` needs to wait for his commitment transaction to be mined into a block and then for the `timelock` period to pass before he can broadcast his timeout transaction. As 20-blocks is used as the `timelock` period in this scenario, 20 blocks are now mined.

```
Block height: 320
```

### 4 - Broadcast Bob's timeout transaction
The chain has advanced 20 blocks so `Bob`'s timeout transaction is now valid - he broadcasts it!

```
Block height: 320
```

### 5 - Replacement cycle begins: build up fee pressure
The replacement cycle involves `Mallory` constructing and broadcasting a replacement chain of transactions (consisting of a `parent` and `child` transaction) that will eventually lead to her out-bidding `Bob`'s timeout transaction. The `parent` transaction is an input to both the `child` transaction and `Mallory`'s pre-image transaction to circumvent BIP-125 Rule #2 when the pre-image transaction is eventually broadcast:
>_"The replacement transaction may only include an unconfirmed input if that input was included in one of the original transactions. (An unconfirmed input spends an output from a currently-unconfirmed transaction)."_

`Mallory` doesn't actually want her replacement chain to be confirmed - she would lose the ability to out-bid `Bob`'s timeout transaction with her pre-image transaction - **the replacement chain is really only a means for fee escalation**. In this scenario, with an otherwise empty mempool, there's no competition for block space, so `Mallory`'s replacement chain would confirm immediately were a block to be mined.

In the real world, there would (likely) be competition for block space, so by slowly bumping the fee rate of her replacement chain she can adapt to the existing fee market as necessary, always ensuring that her replacement chain remains unconfirmed until she is confident that her pre-image transaction will out-bid `Bob`'s timeout transaction.

In this scenario, `Mallory`'s replacement chain is constructed and re-broadcast over a number of replacement rounds, until either one of `Mallory`'s replacement chain transactions is invalid for reasons covered in [Replacement Cycling Attack Failures](#replacement-cycling-attack-failures) or the `replacement_rounds` limit is reached.

```
Block height: 320
```

### 6 - Broadcast Mallory's pre-image TX
`Mallory`'s attempts to broadcast her pre-image transaction to the network, intending to replace via RBF her own `child` transaction as well as `Bob`'s timeout transaction. But what happens next depends on the effective fee rates of the transactions in the mempool and the success of her construction of the replacement chain during the replacement rounds.

If the fee rate of `Mallory`'s pre-image transaction is higher than that of `Bob`'s timeout transaction, `Mallory`'s pre-image broadcast will be successful and `Bob`'s timeout transaction will indeed be replaced by `Mallory`'s pre-image transaction. Once `Mallory`'s pre-image transaction confirms, `Bob`'s funds are effectively stolen!

```
ReplacementCycling1 Bob's timeout TX is not in any mempool, Mallory's Replacement Cycling Attack will succeed once her pre-image TX has confirmed!
...
ReplacementCycling1 Mallory's balance: 99.99987828 BTC
ReplacementCycling1 Bob's balance: 0E-8 BTC
```

If the effective fee rate of `Mallory`'s pre-image transaction (including her replacement chain's `parent` transaction) is lower than that of `Bob`'s timeout transaction, `Mallory`'s pre-image broadcast will fail. This leaves `Bob`'s timeout transaction in the mempool along with `Mallory`'s replacement chain (`parent` and `child` transactions), with all 3 transactions finally confirming. `Bob` gets his funds back!

```
Bob's timeout TX is in at least one mempool, Mallory's Replacement Cycling Attack has failed!
...
ReplacementCycling1 Mallory's balance: 49.99997346 BTC
ReplacementCycling1 Bob's balance: 49.99993244 BTC
```

As above, the scenario will output the balances of `Bob` and `Mallory` to indicate who has ended up with the funds from the output of the commitment transaction. The scenario ends at block height 321:

```
Block height: 321
```

## Scenario limitations
The scenario is a "laboratory" version of a Replacement Cycling attack featuring a highly constrained network (3 nodes), an almost empty (effectively singular) mempool, non-dynamic fee rates and a single iteration of replacement cycle. It allows for very basic experimentation but much of the nuance of the attack is lost in such a simple setup.

A more realistic scenario would feature a network with more nodes, a more dynamic fee market and mempool state and the potential for multiple replacement cycles, with `Bob` discovering that his timeout transaction has disappeared from the mempool leading to `Bob` re-broadcasting a replacement timeout transaction and `Mallory` attacking again. [Scenario 2](./replacement-cycling-2.md) is an attempt at such a scenario!
