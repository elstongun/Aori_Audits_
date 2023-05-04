# Aori Security Review (Draft report)

A security review of the [Aori](https://aori.io) options margin smart contract protocol was done by [Gogo](https://twitter.com/gogotheauditor). \
This audit report includes the vulnerabilities, issues and code improvements found during the security review.

## Disclaimer

"Audits are a time, resource and expertise bound effort where trained experts evaluate smart
contracts using a combination of automated and manual techniques to find as many vulnerabilities
as possible. Audits can show the presence of vulnerabilities **but not their absence**."

\- Secureum

## Risk classification

| Severity           | Impact: High | Impact: Medium | Impact: Low |
| :----------------- | :----------: | :------------: | :---------: |
| Likelihood: High   |   Critical   |      High      |   Medium    |
| Likelihood: Medium |     High     |     Medium     |     Low     |
| Likelihood: Low    |    Medium    |      Low       |     Low     |

### Impact

- **High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.
- **Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.
- **Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

### Likelihood

- **High** - attack path is possible with reasonable assumptions that mimic on-chain conditions and the cost of the attack is relatively low to the amount of funds that can be stolen or lost.
- **Medium** - only conditionally incentivized attack vector, but still relatively likely.
- **Low** - has too many or too unlikely assumptions or requires a huge stake by the attacker with little or no incentive.

### Actions required by severity level

- **Critical** - client **must** fix the issue.
- **High** - client **must** fix the issue.
- **Medium** - client **should** fix the issue.
- **Low** - client **could** fix the issue.

## Executive summary

### Overview

|               |                                                                                                                             |
| :------------ | :-------------------------------------------------------------------------------------------------------------------------- |
| Project Name  | Aori                                                                                                                        |
| Repository    | [https://github.com/elstongun/Aori](https://github.com/elstongun/Aori)                                                      |
| Commit hash   | [b9bdd443a71a77214858349fd7466993c23921ce](https://github.com/elstongun/Aori/tree/b9bdd443a71a77214858349fd7466993c23921ce) |
| Documentation | [https://medium.com/@aori](https://medium.com/@aori)                                                                        |
| Methods       | Manual review                                                                                                               |
|               |

### Issues found

| Severity      | Count |
| :------------ | ----: |
| Critical risk |     5 |
| High risk     |     8 |
| Medium risk   |    10 |
| Low risk      |    17 |

### Scope

| File                                                                                                                                                | SLOC |
| :-------------------------------------------------------------------------------------------------------------------------------------------------- | :--- |
| _Contracts (4)_                                                                                                                                     |
| [src/Margin/MarginManager.sol](https://github.com/elstongun/Aori/blob/b9bdd443a71a77214858349fd7466993c23921ce/Aori/src/Margin/MarginManager.sol)   | 222  |
| [src/Margin/PositionRouter.sol](https://github.com/elstongun/Aori/blob/b9bdd443a71a77214858349fd7466993c23921ce/Aori/src/Margin/PositionRouter.sol) | 265  |
| [src/Margin/Structs.sol](https://github.com/elstongun/Aori/blob/b9bdd443a71a77214858349fd7466993c23921ce/Aori/src/Margin/Structs.sol)               | 102  |
| [src/Margin/Vault.sol](https://github.com/elstongun/Aori/blob/b9bdd443a71a77214858349fd7466993c23921ce/Aori/src/Margin/Vault.sol)                   | 28   |
| _Total (4)_                                                                                                                                         | 617  |

# Findings

| ID                                         | Title                                    | Severity      |
| ------------------------------------------ | :--------------------------------------- | :------------ |
| [\<<index of critical severity finding\>>] | \<<title of critical severity finding\>> | Critical      |
| [\<<index of high severity finding\>>]     | \<<title of high severity finding\>>     | High          |
| [\<<index of medium severity finding\>>]   | \<<title of medium severity finding\>>   | Medium        |
| [\<<index of low severity finding\>>]      | \<<title of low severity finding\>>      | Low           |

## Critical severity

### [C-01] Borrowers can wait to get back their full collateral when option expired ITM

#### **Description**

When borrowers settle their position they have to call MarginManager.settlePosition which will settle the option the first time it is called after option.endingTime(). Borrower collateral amount will be returned based on what is the type of option (pur or call) and whether the option settled in the money or out of the money. This is checked by calling position.option.getITM().

The problem is that position.option.getITM() returns the current status of the option while it has to check the status of the option upon settlement/expiration. Therefore if the option expired in the money but then the price went in the opposite direction and became "out of the money", borrowers will be able to claim their full collateral.

The correct check will have to use settlementPrice instead of the current price fetched from the chainlink oracle if the block.timestamp is pass endingTime.

### [C-02] Attacker can delete the collateral accounting of all borrowers

#### **Description**

An easy to spot mistake was made in the MarginManager.addCollateral. currentCollat is left uninitialized and therefore has default value of 0. Then the new position.collateral is set to currentCollat + collateralToAdd. This will overwrite the collateral the user has deposited with the new one. This issue becomes even more severe as addCollateral has no access control and therefore anyone can call it with collateralToAdd = 0.

Consider calculating the position.collateral in the following way: position.collateral += collateralToAdd.

### [C-03] Positions will become non-liquidatable when collateral value is too low

#### **Description**

The following formula is used to determine the collateral to be given to the liquidator in MarginManager.liquidatePosition:

```solidity
localVars.profit = mulDiv(localVars.collateralVal - localVars.portfolioVal, positionRouter.liquidatorFee(), BPS_DIVISOR);
localVars.collateralToLiquidator = mulDiv(localVars.profit + localVars.portfolioVal, position.collateral, localVars.collateralVal);
doTransferOut(underlying, liquidator, localVars.collateralToLiquidator);
```

The above calculations will fail and revert the transaction when collateralVal is less than the portfolioVal.

This will make very undercollateralized positions non-liquidatable.

Consider refactoring the above formula.

### [C-04] Borrowers can open and settle their position without paying any interest

#### **Description**

Another pretty obvious and quite common vulnerability is that accruePositionInterest is not called when borrowers settle their position.

Since accruePositionInterest is either called externally or from addCollateral, borrowers can decide to not pay the interest they owe to the vault.

Add accruePositionInterest at the beginning of settlePosition.

### [C-05] Wrong interest is paid to lenders for call options

#### **Description**

The interest owed in accruePositionInterest is calculated using the positionRouter.getInterestOwed function which takes as a first parameter the type of the option - call or put.

The problem is that accruePositionInterest always passes `false` for isCall, and therefore interest will be calculated in an incorrect way causing either too big interests or too low to be paid to the lenders.

Pass isCall instead of false.

## High severity

### [H-01] Router keepers can drain manager vaults entirely

#### **Description**

The router keeper role gives the right to certain accounts to open positions in the vault manager. A critical issue is that the `orderbook` is never validated. This can be abused by a privileged keeper account to steal funds in MarginManager vaults. The orderbook is used to retrieve the address of the option and collateral token:

```solidity
address option = address(Orderbook(orderbook).OPTION());
ERC20 token;
if(isCall) {
    token = ERC20(address(AoriCall(option).UNDERLYING()));
    //mint options
    localVars.optionsMinted = lpTokens[token].mintOptions(amountOfUnderlying, option, seatId, account_, true);
```

The problem is that orderbook can be a malicious mock contract that returns and option that is another malicious contract. option.UNDERLYING() can therefore also return any arbitrary value that the keeper picks. Therefore when lpTokens[token].mintOptions is called, amountOfUnderlying will be approved to the malicious option contract. amountOfUnderlying is also not verified which means it can be set to a value like type(uint256).max. The keeper can then take all vaults balances through the malicious option contract.

### [H-02] All collateral from rejected positions request will be stuck forever in the router

#### **Description**

Currently if users want to open a position, they should first make a request through PositionRouter.openShortPositionRequest. To make this request, users provide the collateral they intend to deposit. A privileged account `keeper` then decides what position to execute and what not.

The problem is that if the `keeper` decides not to execute a given position because of e.g. too low collateral:underlyingAmount ratio, the collateral that the user has already deposited will be stuck in the router contract forever, as `rejectIncreasePosition` simply deletes the user position without sending back their collateral amount.

Consider returning users collateral if their request was rejected.

### [H-03] Borrow rate is used instead of initial margin rate

#### **Description**

The margin rate logic seems flawed on several places. When MarginManager.openShortPosition is called, position.entryMarginRate is set to positionRouter.getBorrowRate(token); instead of positionRouter.getInitialMargin(token).

However, this value itself is not a big problem as it is later only used in getInterestOwed as a parameter that is overwritten. In getInterestOwed, two of the passed parameters are overwritten in the following way:

```solidity
underlying = ERC20(address(call.UNDERLYING()));
entryMarginRate = getBorrowRate(underlying);
```

The first one does not change its actual value, but the second one does change it and again assigns it to getBorrowRate instead of getInitialMargin.

Consider verifying the formula used to calculate the owed interest and determine whether it is intended to use the borrow rate or the initial margin rate.

### [H-04] Opening positions will DoS after first positions for zero-to-non-zero allowance tokens

#### **Description**

Well known issue regarding tokens like USDT, MANA, etc. that contain the following safety check in their .approve method:

```solidity
function approve(address _spender, uint _value) public onlyPayloadSize(2 * 32) {

    // To change the approve amount you first have to reduce the addresses`
    //  allowance to zero by calling `approve(_spender, 0)` if it is not
    //  already 0 to mitigate the race condition described here:
    //  https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
    require(!((_value != 0) && (allowed[msg.sender][_spender] != 0)));

    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
}
```

### [H-05] Assumption on collateral token precision leads to wrong liquidation flow

#### **Description**

This is an issue that occurs on many places around the codebase. Decimals of collateral token are assumed on several places to be 18. PositionRouter.isLiquidatable returns the collateral value by calculating it in the following way:

```solidity
collateralVal = mulDiv(getPrice(manager.oracles(token)), collateral, expScale);
```

The problem comes from that the divisor is `expScale` which is set to `1e18` while the `collateral` can be in different precision (e.g. 6, 8, 12, 24). This will lead to wrong values returned to the MarginManager on liquidations.

Consider using 10*\*IERC20(token).decimals(), instead of expScale.

### [H-06] Initial margin returns wrong value for tokens with decimals != 18

#### **Description**

Same issue as above, `optionSize` is assumed to be scaled by 1e18 since the `expScale` is again used as a divisior.

Consider using 10*\*IERC20(token).decimals(), instead of expScale.

### [H-07] Wrong usdc-scaled price will be returned when Chainlink token's USD price feed's decimals != 8

#### **Description**

Some token/usd price feed oracles do not return a price with 8 decimals precision which is assumed in the code e.g. [AMPL/USD price feed has 18 decimals](https://etherscan.io/address/0xe20CA8D7546932360e37E9D72c1a47334af57706#readContract).

Consider implementing the following change:

```diff
-   return (uint256(price) / (10**2))
+   return (uint256(price) / (10**(oracle.decimals() - USDC.decimals()))
```

### [H-08] First depositor inflation attack on vault

#### **Description**

Very well known attack vector regarding ERC4626 vaults, see explanation [here](https://github.com/sherlock-audit/2022-08-sentiment-judging/blob/main/004-H/1-report.md).

## Medium severity

### [M-01] Token vaults and price oracles can be overwritten in margin manager

#### **Description**

whitelistAsset can be called multiple times which give the owner of the MarginManager the ability to input any malicious oracle or vault addresses.

Consider reverting if whitelistedAssets[token] == true.

### [M-02] User positions will be overwritten when executed in the same block

#### **Description**

If multiple open position requests of the same account are execured in the same block which can happen in a batch transaction, the second user position may have the same positionKey as the first one and therefore overwrite the first one loosing the user's collateral.

Consider using a nonce in getPositionKey.

### [M-03] Position collateral amount not validated against initial margin

#### **Description**

The initial margin is currently not used to validate the borrower collateral. Therefore the underlyingAmount in MarginManager.openShortPosition can be extremely high compared to collateral. Consider validating that collateral is above the initial margin rate.

### [M-04] Hardcoded USDC decimals assume same precision around different blockchains

#### **Description**

USDC decimals on most blockchain are 6, but on BSC are 18 which will cause serious issues if the contracts are to be deployed on BSC. Since the project has stated that it will be deployed on multiple blockchains but not BSC yet, this issue is assigned of medium severity.

### [M-05] Position router can be re-initialized by contract owner

#### **Description**

PositionRouter.initialize set some critical variables like manager, callFactory and putFactory that should not be set more than once. Consider preventing the initialize method from being called more than once.

### [M-06] Rebasing and fee-on-transfer underlying tokens not handled properly

#### **Description**

There are multiple places where fee-on-transfer and rebasing token transfers are not handled correctly. Consider either noting that such tokens will not be supported as underlying/collateral assets or fix the flawed functions.

### [M-07] No input validation on privileged functions

#### **Description**

e.g. liquidatorFee can be set to value like type(uint256).max to make liquidations impossible. Consider adding some limits.

### [M-08] Malicious users can grief borrowers to prevent them from adding necessary collateral

#### **Description**

addCollateral is used by borrowers to deposit more collateral in case they are close to liquidations. addCollateral calls accruePositionInterest every time which is a public function with not access control. accruePositionInterest reverts if no time has passed since last accrual. Therefore accruePositionInterest can be called each time by an attacker to prevent borrowers calls to addCollateral from executing.

Consider returning 0 instead of reverting if block.timestamp == lastAccrueTime

### [M-09] Non-standard ERC20 token vulnerabilities

#### **Description**

Some tokens like USDT do not return a value on .transfer, .transferFrom and .approve, therefore all transaction will revert if the SafeERC20 library is not used. There are several more flaws regarding non-standard ERC20 tokens that should be added.

### [M-10] Inherited method of ERC4626 vault seem forgotten

#### **Description**

Custom code is added to the deposit and withdraw functions in Vault.sol like the nonReentrant modifier, while the inherited deposit, withdraw, mint and redeem functions are public on the contract as they are inherited from the ERC4626 contract. A specific concern is the following comment in the mint function:

```
 * As opposed to {deposit}, minting is allowed even if the vault is in a state where the price of a share is zero.
 * In this case, the shares will be minted without requiring any assets to be deposited.
```

Also, any further logic like validation input validation or shares manipulation in Vault.depositAssets and Vault.withdrawAssets would be redundant as users will be able to simply call the public deposit and withdraw methods.

Consider `override`in the deposit and withdraw methods and remove the redeem and mint methods.
