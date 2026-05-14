# K2 Protocol — Code4rena Audit Findings

## Contest: 2026-04-k2 | Prize Pool: $135,000 USDC
## Language: Rust (Soroban Smart Contracts)

---

## Finding H-01: Stale Price Cache Bypass via TTL-Threshold Mismatch

### Severity: HIGH

### Summary

The price oracle implements two independent freshness mechanisms — `price_cache_ttl` (TTL cache duration) and `price_staleness_threshold` (max price age) — that are **not coupled**. If `cache_ttl > staleness_threshold`, the cache can serve prices that are stale relative to the protocol's intended freshness guarantees. Critical operations (liquidation, borrowing) will use these stale prices.

### Vulnerable Code

`contracts/price-oracle/src/contract.rs`, lines 365–379:

```rust
let cache_ttl = storage::get_price_cache_ttl(&env);  // Independent config
if cache_ttl > 0 {
    if let Some(cached) = storage::get_last_price_data(&env, &asset) {
        let current_time = env.ledger().timestamp();
        let cache_age = current_time.saturating_sub(cached.cached_at);
        let price_age = current_time.saturating_sub(cached.timestamp);
        // BUG: cache_age <= cache_ttl is independent of price_age <= staleness_threshold
        if cache_age <= cache_ttl && price_age <= oracle_config.price_staleness_threshold {
            return Ok(price_data);  // Returns potentially stale cached price
        }
    }
}
```

`contracts/price-oracle/src/contract.rs`, lines 387–393 (per-asset override):
```rust
oracle::query_batch_adapter_direct(
    &env, &adapter, &feed_id, decimals,
    config.max_age,  // ← Can be up to 86400s, bypassing 1-hour default
    oracle_config.price_precision,
    oracle_config.price_staleness_threshold,
)?
```

### Proof of Concept

```
Config: price_cache_ttl = 7200s, price_staleness_threshold = 3600s

T=0:     Reflector publishes $100 for XLM. Cache written (valid until T=7200).
         Oracle node goes offline (stops publishing).

T=3500:  XLM price drops 40% to $60 in the market.
T=3700:  Liquidator calls liquidation_call for underwater borrower.
         Oracle returns $100 from cache (cache_age=3700 < 7200 ✓).
         Health factor calculated with $100: borrower NOT liquidatable.
         
Expected: Borrower liquidatable with fresh price ($60).
Actual:   Stale $100 price prevents liquidation.
```

### Impact

Liquidation front-running, improper borrowing against inflated collateral, under-liquidatable positions during oracle outages.

---

## Finding H-02: Malicious DEX Handler Can Steal Liquidation Collateral via Fake Output

### Severity: HIGH

### Summary

The `swap_via_handler` function in `contracts/shared/src/dex.rs` transfers input tokens to a handler, then verifies only that the **recipient's output token balance increased** by at least `min_out`. A whitelisted malicious handler can bypass the swap entirely by transferring `min_out` tokens from its own pre-funded reserves to the recipient, keeping the input tokens as pure profit.

### Vulnerable Code

`contracts/shared/src/dex.rs`, lines 367–453:

```rust
// STEP 1: Transfer user's tokens to handler (unconditional)
let _: () = env.invoke_contract(from_token, &transfer_sym, 
    vec![caller, handler, amount_in]);

// STEP 2: Check recipient's to_token balance BEFORE
let balance_before = env.invoke_contract(to_token, &balance_sym, vec![recipient]);

// STEP 3: Call handler's execute_swap
let reported_amount_out = call_soroswap(handler, "execute_swap", ...)?;
// ↑ Reported amount is NEVER compared to actual balance change!

// STEP 4: Check recipient's to_token balance AFTER
let balance_after = env.invoke_contract(to_token, &balance_sym, vec![recipient]);
let actual = balance_after.checked_sub(balance_before).unwrap();

// STEP 5: Only verify balance increase >= min_out
if actual < min_out { return Err(InsufficientSwapOut); }
// ↑ NO verification that handler used the input tokens!

Ok(actual)
```

### Proof of Concept

Malicious handler:
```rust
pub fn execute_swap(env, from, to, amount_in, min_out, recipient) -> u128 {
    // Receives amount_in tokens from router (user's seized collateral)
    // DON'T SWAP. Just send min_out from our reserves to recipient.
    token::Client.transfer(handler, recipient, min_out);
    min_out  // Return value ignored
}
```

Attack: Liquidator liquidates borrower, router swaps 10.5 ETH via malicious handler. Handler sends 10,000 USDC from its reserves to router, keeps 10.5 ETH. Profit: ~$525 + 10.5 ETH.

### Impact

Theft of liquidation collateral, user fund loss in swap_collateral, potential protocol insolvency at scale.

---

## Finding M-01: Liquidation Callback Partial Failure Causes State Desynchronization

### Severity: MEDIUM

### Summary

In `execute_operation` (flash_loan.rs, line 337), `LiquidationCallbackParams` are unconditionally cleared after `execute_liquidation_callback`, regardless of success or failure. If the callback partially executes (debt burned, collateral seized in persistent storage) but then reverts (e.g., DEX swap fails), the protocol enters an inconsistent state: user's positions are modified but the liquidation cannot be retried because params are gone and the authorization may have expired.

### Vulnerable Code

`contracts/kinetic-router/src/flash_loan.rs`, lines 329–342:

```rust
let callback_params = storage::get_liquidation_callback_params(&env).unwrap();
let result = execute_liquidation_callback(env.clone(), callback_params);

// ALWAYS clear params — even if callback failed
storage::remove_liquidation_callback_params(&env);

match result {
    Ok(_) => true,
    Err(_) => false,  // Params are gone, cannot retry
}
```

Within `execute_liquidation_callback`:
```rust
// STEP 1: Burn debt (persistent storage) — IRREVERSIBLE
env.invoke_contract(debt_token, "burn_scaled", ...);  // OK

// STEP 2: Burn aTokens + transfer collateral (persistent) — IRREVERSIBLE  
env.invoke_contract(a_token, "burn_scaled_and_transfer_to", ...);  // OK

// STEP 3: DEX swap — CAN FAIL
swap_via_handler(...)?;  // FAILS → callback returns Err

// DEBT AND COLLATERAL ALREADY MODIFIED IN PERSISTENT STORAGE
```

### Proof of Concept

1. `prepare_liquidation` → auth stored (5 min expiry)
2. `execute_liquidation`:
   a. Flash loan transfers debt token to pool ✓
   b. `execute_liquidation_callback`:
      - Debt burned from user (persistent) ✓
      - Collateral transferred to pool (persistent) ✓
      - DEX swap fails (no liquidity) ❌
   c. Callback returns Err, execute_operation returns false
3. Flash loan verify_repayment fails, entire TX reverts
4. **BUT**: Persistent storage in debt_token and aToken contracts NOT reverted
5. User: 0 debt, reduced collateral → inconsistent state

### Impact

Irreversible state corruption, stuck collateral, fund loss, requires manual admin recovery.

---

## Finding M-02: Weighted-Average Liquidation Threshold Staleness Enables Unsafe Withdrawals

### Severity: MEDIUM

### Summary

`validate_user_can_withdraw` computes post-withdrawal health factor by subtracting the withdrawn asset's contribution from `weighted_threshold_sum`. Both the original accumulation and the withdrawal contribution use **U256 → u128 truncation** at each step. This double-truncation can inflate the post-withdrawal health factor, allowing users to withdraw collateral that should keep them liquidatable.

### Vulnerable Code

`contracts/kinetic-router/src/calculation.rs`, lines 284–295:
```rust
let weighted_threshold_value = balance_u256
    .mul(&price_u256).mul(&oracle_to_wad_u256).mul(&threshold_u256)
    .div(&decimals_pow_u256)
    .to_u128()  // ← Truncation: U256 → u128
    .ok_or(...)?;
weighted_threshold_sum += weighted_threshold_value;  // Sum of truncated values
```

`contracts/kinetic-router/src/validation.rs`, lines 291–305:
```rust
let withdraw_contribution = { /* same U256→u128 truncation */ };
let new_sum = weighted_threshold_sum
    .checked_sub(withdraw_contribution)
    .unwrap_or(0);  // ← Silent default on underflow
```

### Proof of Concept

```
User portfolio:
  Asset A: 10,000 USDC, threshold=85%, contribution ≈ X (truncated)
  Asset B: 10,000 XLM,  threshold=65%, contribution ≈ Y (truncated)
  Debt: $14,000
  Weighted sum = X + Y (each truncated independently)

Withdrawal of Asset A:
  Expected new sum = Y
  Actual new sum = (X + Y) - floor(Y_contribution_from_A_balance)
  
Since truncation at each step floors each contribution independently:
  (X + Y) ≥ true_sum
  floor(Y_contribution) ≤ true_Y_contribution
  new_sum ≥ true_new_sum
  
Post-withdrawal HF = new_sum × WAD / (10000 × debt)
                   ≥ true_HF
                   
For boundary positions (HF ≈ 0.999… WAD), this inflation can push 
HF ≥ WAD, incorrectly allowing the withdrawal.
```

### Impact

Unsafe withdrawals, protocol undercollateralization, cascading liquidations at scale.

---

## Finding L-01: Price Normalization Truncation Bias [LOW]

`contracts/price-oracle/src/oracle.rs`, line 219: Floor division (`checked_div`) when scaling down prices undervalues collateral by up to `(scale-1)/scale` per asset.

## Finding L-02: Whitelist/Blacklist Priority Ambiguity [LOW]

Both whitelist and blacklist checks exist but priority is implicit (whitelist checked first → blacklist overrides). No explicit documentation.

## Finding L-03: Liquidation HF Boundary Check [LOW]

`contracts/liquidation-engine/src/calculation.rs`, line 24: Uses `>= WAD` to block liquidation, preventing liquidation of positions at exactly HF = 1.0.

---

## References

- Repository: https://github.com/code-423n4/2026-04-k2
- Soroban SDK: https://soroban.stellar.org/
- Key constants: `WAD = 10^18`, `RAY = 10^27`, `PRICE_PRECISION = 14 decimals`
- Affected files by line number detailed in full report
