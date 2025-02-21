# Replacement Cycling Scenario 1

## Configuration and execution

The scenario, implemented in [scenarios/replacement_cycling_1.py](./scenarios/replacement_cycling_1.py), can be configured via the following parameters:
- `--replacement-rounds`: The number of replacement rounds to execute before the final stage of the attack, the broadcast of `Mallory`'s "winning" pre-image transaction.
- `--base_fee`: The initial/base fee rate (`sats/vbyte`) to use the replacement rounds.
- `--fee_increment`: The fee rate increment (`sats/vbyte`) to apply each replacement round.

## Potential issues

## Scenario breakdown

### 0 - Setup: network, keys & wallets, funding and mining

### 1 - Open channel

### 2 - Construct commitment, timeout and pre-image transactions



### 3 - Broadcast Bob's commitment transaction
Let's assume that Mallory now decides to withhold the pre-image for the HTLC from Bob. Bob decides to broadcast his commitment transaction to the network. We're doing this just 1 block after the channel was opened in this scenario for simplicity. In reality this would be some time after the channel was opened and the HTLC `cltv_expiry` has passed. Note that this means that the commitment transaction does not include a HTLC expiry in its construction, it's intended to be broadcast as if the HTLC expiry has already passed.

Now Bob needs to wait for his commitment transaction to be mined into a block and then the `timelock` period before he can broadcast his timeout transaction. In this scenario were using 20-blocks as the `timelock` period.

### 4 - Broadcast Mallory's "to-replace" TX chain, Bob's timeout TX and Mallory's pre-image TX
The chain has advanced 20 blocks so Bob's timeout transaction would now be valid. In this scenario, before Bob broadcasts his timeout transaction, Mallory broadcasts her low fee-rate "to-replace" chain consisting of a `parent` and `child`. As a reminder, the `parent` transaction is also an input to the pre-image transaction because of BIP-125 Rule #2 (_"The replacement transaction may only include an unconfirmed input if that input was included in one of the original transactions. (An unconfirmed input spends an output from a currently-unconfirmed transaction"_). 

When Bob broadcasts his timeout transaction shortly thereafter (and after the mempools have been synced), we can see that there are then 3 transactions in each nodes mempool:
```
Mallory broadcasts her "to-replace" chain at block height 320
Mallory parent txid: 84d49842...
Mallory child txid: 6dd4ff3e...

Mallory mempool: ['84d49842...', '6dd4ff3e...']
Bob mempool: ['84d49842...', '6dd4ff3e...']

Bob broadcasts his HTLC timeout transaction at block height 320
Bob timeout txid: 033054ca...

Mallory mempool: ['033054ca...', '84d49842...', '6dd4ff3e...']
Bob mempool: ['033054ca...', '84d49842...', '6dd4ff3e...']
```

### 5 - Broadcast Mallory's pre-image transaction
Mallory broadcasts her pre-image transaction to the network. This pre-image has 2 inputs which are both spending the exact same outputs as 2 of the 3 transactions in the mempool:
1. The first input is spending the same output as Bob's timeout transaction - the output of the commitment transaction.
2. The second input is spending the same output as the `child` transaction in her "to-replace" chain.
As such due to RBF Mallory's pre-image transaction will replace both Bob's timeout transaction and her own `child` transaction. This leaves just the `parent` of Mallory's "to-replace" chain and Mallory's pre-image transaction in the mempool. This is bad news for Bob!!

### 6 - 



