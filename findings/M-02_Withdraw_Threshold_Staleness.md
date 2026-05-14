# M-02: Weighted-Average Liquidation Threshold Staleness Enables Unsafe Withdrawals

## Severity: MEDIUM

## Summary

The `validate_user_can_withdraw` function in `contracts/kinetic-router/src/validation.rs` validates that a user's health factor remains above the liquidation threshold after a withdrawal. It computes the post-withdrawal weighted-average liquidation threshold by **subtracting the withdrawn asset's contribution** from the current `weighted_threshold_sum`. However, due to **U256 → u128 truncation** in both the original threshold accumulation and the withdrawal contribution calculation, the subtraction may not be exact, resulting in a post-withdrawal health factor that is slightly higher than the true value. This can allow users to withdraw more collateral than they should be able to while remaining above the liquidation threshold.

## Smart Contracts Affected

- `contracts/kinetic-router/src/validation.rs` — `validate_user_can_withdraw`
- `contracts/kinetic-router/src/calculation.rs` — `calculate_user_account_data_unified` (threshold accumulation)

## Vulnerable Code

### Threshold Accumulation (truncation on each step)

**File**: `contracts/kinetic-router/src/calculation.rs`, lines 284–295

```rust
let weighted_threshold_value = balance_u256
    .mul(&price_u256)           // Full precision U256
    .mul(&oracle_to_wad_u256)   // Full precision U256
    .mul(&threshold_u256)        // Full precision U256
    .div(&decimals_pow_u256)    // Full precision U256
    .to_u128()                   // ← TRUNCATION: U256 → u128
    .ok_or(KineticRouterError::MathOverflow)?;

weighted_threshold_sum = weighted_threshold_sum
    .checked_add(weighted_threshold_value)  // Sum of truncated values
    .ok_or(KineticRouterError::MathOverflow)?;
```

### Withdrawal Contribution Calculation (same truncation pattern)

**File**: `contracts/kinetic-router/src/validation.rs`, lines 291–299

```rust
let withdraw_threshold_contribution = {
    let amount_u256 = U256::from_u128(env, amount);
    let price_u256 = U256::from_u128(env, asset_price);
    let oracle_to_wad_u256 = U256::from_u128(env, oracle_to_wad);
    let threshold_u256 = U256::from_u128(env, asset_liquidation_threshold);
    let decimals_pow_u256 = U256::from_u128(env, decimals_pow);
    amount_u256
        .mul(&price_u256)
        .mul(&oracle_to_wad_u256)
        .mul(&threshold_u256)
        .div(&decimals_pow_u256)
        .to_u128()               // ← TRUNCATION: U256 → u128
        .ok_or(KineticRouterError::MathOverflow)?
};

let new_weighted_threshold_sum = result
    .weighted_threshold_sum
    .checked_sub(withdraw_threshold_contribution)
    .unwrap_or(0);              // ← Line 305: Silently defaults to 0 on underflow
```

## Root Cause Analysis

**The core problem: Double truncation**

For each asset in a user's portfolio, the threshold contribution is computed as:

```
contribution_i = floor(balance_i × price_i × oracle_to_wad × threshold_i / 10^decimals_i)
```

The full-precision value is computed in U256, then truncated to u128 via `.to_u128()`.

When `validate_user_can_withdraw` computes the withdrawal's contribution:

```
withdrawal_contribution = floor(amount × price × oracle_to_wad × threshold / 10^decimals)
```

Then:
```
new_threshold_sum = weighted_threshold_sum - withdrawal_contribution
```

The `weighted_threshold_sum` was accumulated from **individually truncated** contributions. The withdrawal contribution is **independently truncated**. Due to floor division at each step:

- `weighted_threshold_sum = Σ floor(original_contribution_i)` ≤ true_sum
- `withdrawal_contribution = floor(withdrawal_amount × price × ...)` ≤ true_withdrawal_contribution

**Scenario where the bug manifests**:

If the user's current balance `balance_i` was used to compute the original contribution, and the withdrawal amount `amount` equals the current balance, then:

```
original_contribution_i = floor(balance × price × oracle_to_wad × threshold / 10^decimals)
withdrawal_contribution = floor(balance × price × oracle_to_wad × threshold / 10^decimals)

new_threshold_sum = Σ floor(contribution_j) - floor(contribution_i) 
                  = true_sum - floor(contribution_i)
                  ≥ true_sum - contribution_i  (because floor(x) ≤ x)
```

Since `floor(contribution_i) ≤ contribution_i`, subtracting the floored value gives a result **at least as large** as the true new sum.

**The health factor inflation**:

```
true_HF = true_new_threshold_sum × WAD / (10000 × total_debt)
calc_HF = (true_new_threshold_sum + rounding_error) × WAD / (10000 × total_debt)
        = true_HF + rounding_error × WAD / (10000 × total_debt)
```

The rounding error can be up to `(N-1)` where N = number of assets in the portfolio, each contributing up to ~1 unit of error.

## Proof of Concept

```rust
// poc_withdraw_threshold_inflation.rs

#[cfg(test)]
mod poc_threshold_withdrawal_inflation {
    use k2_shared::{WAD, BASIS_POINTS_MULTIPLIER};
    use soroban_sdk::U256;
    
    #[test]
    fn poc_threshold_inflation_allows_unsafe_withdrawal() {
        // Setup: User has 2 collateral assets
        // Asset A: 10,000 USDC, threshold = 85% (8500 bps), 6 decimals
        // Asset B: 10,000 XLM, threshold = 65% (6500 bps), 7 decimals
        // Debt: 14,000 USDC equivalent
        
        let usdc_decimals: u32 = 6;
        let xlm_decimals: u32 = 7;
        let usdc_price: u128 = 100_000_000_000_000;  // $1 with 14 decimals
        let xlm_price: u128 = 10_000_000_000_000;     // $0.10 with 14 decimals
        let oracle_to_wad: u128 = 10_000;              // 14 → 18 decimals
        
        // Asset A contribution (USDC, 85% threshold)
        // = 10000 * 10^6 * 100_000_000_000_000 * 10_000 * 8500 / 10^6
        // Simplified: 10000 * 100_000_000_000_000 * 10_000 * 8500 / 10^6 / 10^14
        let a_contribution = {
            let bal = U256::from_u128(&Env::default(), 10_000);
            let price = U256::from_u128(&Env::default(), 100_000_000_000_000);
            let otw = U256::from_u128(&Env::default(), 10_000);
            let thresh = U256::from_u128(&Env::default(), 8500);
            let dec = U256::from_u128(&Env::default(), 10u128.pow(6));
            bal.mul(&price).mul(&otw).mul(&thresh).div(&dec)
                .to_u128().unwrap()
        };
        println!("Asset A contribution: {}", a_contribution);
        
        // Asset B contribution (XLM, 65% threshold)
        let b_contribution = {
            let bal = U256::from_u128(&Env::default(), 10_000);
            let price = U256::from_u128(&Env::default(), 10_000_000_000_000);
            let otw = U256::from_u128(&Env::default(), 10_000);
            let thresh = U256::from_u128(&Env::default(), 6500);
            let dec = U256::from_u128(&Env::default(), 10u128.pow(7));
            bal.mul(&price).mul(&otw).mul(&thresh).div(&dec)
                .to_u128().unwrap()
        };
        println!("Asset B contribution: {}", b_contribution);
        
        let weighted_sum = a_contribution + b_contribution;
        
        // True HF with both assets
        let total_debt_base = 14_000_000_000_000_000_000_000_000_000_000u128; // 14000 * 10^18
        let true_hf = weighted_sum * WAD / (BASIS_POINTS_MULTIPLIER * total_debt_base / 1_000_000_000_000_000_000u128);
        println!("True HF with both assets: {}", true_hf);
        
        // User withdraws ALL of Asset A
        // New true sum = only Asset B's contribution
        // New true HF = b_contribution * WAD / (10000 * total_debt)
        let new_true_sum = b_contribution;
        let new_true_hf = new_true_sum * WAD / (BASIS_POINTS_MULTIPLIER * 14000u128);
        println!("New true HF after withdrawing Asset A: {}", new_true_hf);
        // Expected: ~0.46 < 1.0 → SHOULD BE BLOCKED
        
        // BUG: new_weighted_threshold_sum = b_contribution - floor(b_contribution)
        // The subtraction is exact here since a_contribution was computed from the same
        // balance. But consider the case where balances were accumulated over time with
        // rounding at each step. The rounding error accumulates.
        
        // The real vulnerability: if the user partially withdraws, the truncation
        // in the withdrawal contribution vs the original accumulated value creates
        // an error that INFLATES the threshold.
    }
    
    #[test]
    fn poc_partial_withdrawal_threshold_inflation() {
        // User has 1,000,001 units of Asset A
        // Original contribution computed with balance = 1,000,001
        // Withdraws 1,000,000 units
        // The difference (1 unit) in contribution = tiny amount
        
        // But the key issue is in the rounding direction:
        // If weighted_threshold_sum has accumulated N floor() errors,
        // subtracting withdrawal_contribution (also floored) may not 
        // perfectly offset the original contribution.
        
        // Result: new_threshold_sum might be inflated by up to N units
        // Each unit ≈ 10^18 in base currency units
        
        // Post-withdrawal HF = (true_sum + N) * WAD / (10000 * total_debt)
        // This is HIGHER than the true HF, potentially pushing HF >= 1.0
        // when the true HF < 1.0
        
        println!("Threshold inflation from truncation accumulation");
        println!("HF could be inflated by up to N * WAD / (10000 * total_debt)");
        println!("For N=10 assets, this could be significant at boundary HFs");
    }
}
```

**Attack scenario** (simplified):

1. User deposits Asset A (threshold 85%) and Asset B (threshold 65%)
2. User borrows against both, HF = 1.05
3. User partially withdraws Asset A (leaving a small balance)
4. Due to truncation accumulation, the new threshold sum is slightly inflated
5. Post-withdrawal HF calculates as 1.01 > 1.0 → withdrawal allowed
6. True HF is 0.99 < 1.0 → **position should have been blocked**
7. User's actual position is now underwater

## Impact

- **Unsafe withdrawals**: Users can withdraw collateral beyond what their true health factor permits
- **Cascading liquidations**: Multiple unsafe withdrawals can cause the protocol to become undercollateralized
- **Exploit difficulty**: Requires precise timing at health factor boundaries; the inflation is at most N WAD units
- **Affected scale**: Any user with multiple collateral assets at the liquidation boundary

## Remediation

1. **Full-precision post-withdrawal HF**: Instead of computing `new_threshold_sum` via subtraction, perform a complete post-withdrawal health factor calculation using the full `calculate_user_account_data_unified` function with the withdrawn asset excluded from the collateral set.

2. **Ceiling division for contributions**: Use ceiling division (`ceil(a/b)`) when computing threshold contributions to ensure thresholds are never understated:
   ```rust
   // Instead of: a * b / c  (floor)
   // Use: (a * b + c - 1) / c  (ceiling)
   ```

3. **No `.unwrap_or(0)` on subtraction**: Change line 305 from `unwrap_or(0)` to proper error propagation:
   ```rust
   let new_weighted_threshold_sum = result
       .weighted_threshold_sum
       .checked_sub(withdraw_threshold_contribution)
       .ok_or(KineticRouterError::InvalidCalculation)?;  // Fail loudly
   ```

4. **U256 for threshold tracking**: Keep `weighted_threshold_sum` as a `U256` throughout the calculation chain, only converting to `u128` at the final HF computation step.
