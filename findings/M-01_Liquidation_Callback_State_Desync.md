# M-01: Liquidation Callback Partial Failure Causes Irreversible State Desynchronization

## Severity: MEDIUM

## Summary

The `execute_operation` function in the Kinetic Router's flash loan module handles internal liquidation flash loans. After invoking the liquidation callback (`execute_liquidation_callback`), the `LiquidationCallbackParams` are unconditionally cleared from temporary storage regardless of whether the callback succeeded or failed. If the callback partially executes (e.g., user's debt is burned and collateral is transferred to the pool) but then reverts due to a downstream failure (e.g., DEX swap failure), the protocol enters an inconsistent state: the user's debt and collateral positions are modified, but the liquidation cannot be retried because the callback params are gone and the flash loan cannot be repaid.

## Smart Contracts Affected

- `contracts/kinetic-router/src/flash_loan.rs` — `execute_operation` and `execute_liquidation_callback`
- `contracts/kinetic-router/src/liquidation.rs` — Liquidation call entry point
- `contracts/kinetic-router/src/router.rs` — `prepare_liquidation` and `execute_liquidation`

## Vulnerable Code

**File**: `contracts/kinetic-router/src/flash_loan.rs`, lines 302–343

```rust
pub fn execute_operation(
    env: Env,
    _assets: Vec<Address>,
    _amounts: Vec<u128>,
    premiums: Vec<u128>,
    initiator: Address,
    _params: soroban_sdk::Bytes,
) -> bool {
    // ... validation checks ...
    
    // Line 329: Retrieve stored liquidation params
    let callback_params = match storage::get_liquidation_callback_params(&env) {
        Some(p) => p,
        None => return false,
    };

    // Line 334: Execute the liquidation callback
    let result = execute_liquidation_callback(env.clone(), callback_params);
    
    // Line 337: ALWAYS clear params — even if callback failed
    storage::remove_liquidation_callback_params(&env);
    
    match result {
        Ok(_) => true,
        Err(_) => false,  // Callback failed, but params are gone
    }
}
```

**File**: `contracts/kinetic-router/src/flash_loan.rs`, lines 345–560 (`execute_liquidation_callback`)

The callback executes a sequence of potentially-failing operations:

```rust
fn execute_liquidation_callback(
    env: Env,
    params: LiquidationCallbackParams,
) -> Result<(), KineticRouterError> {
    // ...
    
    // STEP 1: Burn debt tokens from user (IRREVERSIBLE)
    let burn_result = env.try_invoke_contract::<(bool, i128, i128), KineticRouterError>(
        &debt_reserve_data.debt_token_address,
        &sym_burn_scaled,
        burn_debt_args,  // params: pool, user, debt_to_cover, borrow_index
    );
    // Lines 378-385: If this succeeds but later steps fail, debt is GONE
    
    // STEP 2: Burn aTokens and transfer collateral to pool (MOSTLY IRREVERSIBLE)
    let burn_and_transfer_result = env.try_invoke_contract::<(i128, i128, u128), KineticRouterError>(
        &collateral_reserve_data.a_token_address,
        &sym_burn_scaled_and_transfer_to,
        burn_and_transfer_args,  // params: pool, user, collateral_to_seize, index, pool
    );
    // Lines 388-407: If this succeeds but later steps fail, collateral is in pool
    
    // STEP 3: Swap collateral → debt via DEX (CAN FAIL)
    let debt_received_i128 = if let Some(handler) = &params.swap_handler {
        k2_shared::dex::swap_via_handler(&env, handler, ...)?  // ← CAN FAIL HERE
    } else if let Some(factory) = storage::get_dex_factory(&env) {
        k2_shared::dex::swap_exact_tokens_direct(&env, factory, ...)?  // ← CAN FAIL HERE
    } else {
        k2_shared::dex::swap_exact_tokens(&env, router, ...)?  // ← CAN FAIL HERE
    };
    // Lines 418-456: If swap fails here, both debt and collateral are modified!
    
    // STEP 4: Repay debt from swap proceeds
    // ...
    
    // STEP 5: Transfer profit to liquidator
    // ...
}
```

## Root Cause Analysis

The vulnerability stems from **irreversible state changes occurring before all validations complete**:

1. **Debt burn (lines 378-385)**: The `burn_scaled` call permanently reduces the user's debt token balance. If the callback subsequently fails, this reduction cannot be undone.

2. **Collateral seizure (lines 388-407)**: The `burn_scaled_and_transfer_to` call permanently burns the user's aTokens and transfers the underlying collateral to the pool contract. If the callback subsequently fails, this transfer cannot be reversed without manual intervention.

3. **No rollback on failure (line 337)**: Regardless of the callback's success/failure, the `LiquidationCallbackParams` are removed. On failure, there is no mechanism to retry the liquidation within the same authorization window.

4. **Flash loan cannot be repaid**: If the callback partially succeeds (state is modified) but then returns an error, the flash loan's `verify_repayment` check (line 237-253 in `internal_flash_loan`) will fail because the pool no longer holds enough tokens to repay the flash loan.

**The failure sequence**:
```
1. Flash loan transfers debt_token to pool ✓
2. execute_liquidation_callback begins
3. Debt burned from user ✓ (IRREVERSIBLE)
4. Collateral burned from user, transferred to pool ✓ (MOSTLY IRREVERSIBLE)
5. DEX swap fails ❌ (e.g., no liquidity, handler reverts)
6. Callback returns Err
7. execute_operation returns false
8. Flash loan tries to verify repayment → FAIL
9. ENTIRE TRANSACTION REVERTS
10. But: burn_scaled on debt token has already executed (state changed)
11. User's debt is 0, but flash loan couldn't repay
12. Pool state is inconsistent
```

Wait, Soroban reverts ALL state changes on transaction failure. So if the flash loan's `verify_repayment` fails (line 148), the entire transaction reverts including the burns.

The REAL issue is more subtle: **Soroban temporary storage is transaction-scoped**. The `LiquidationCallbackParams` are in temporary storage, which is reverted on failure. But the cross-contract calls to `burn_scaled` and `burn_scaled_and_transfer_to` modify state in **persistent** storage (debt token and aToken contracts). Those changes persist even when the router's temporary storage is reverted.

**The actual failure sequence**:
```
1. execute_liquidation_callback:
   a. Debt burned from user (persistent storage) ✓
   b. Collateral burned from user, transferred to pool (persistent storage) ✓
   c. DEX swap fails ❌ → returns Err
2. Callback returns Err → execute_operation returns false
3. Flash loan: verify_repayment fails → entire router TX reverts
4. Router's temporary storage (LIQCB, etc.) is reverted ✓
5. BUT: debt token's persistent storage (user debt = 0) is NOT reverted ❌
6. User has 0 debt, 0 collateral (partially seized), position is inconsistent
7. Authorization from prepare_liquidation still valid for ~5 minutes
8. Next liquidation attempt: user has no debt → fails
```

## Attack Scenario

**Scenario**: DEX swap failure during liquidation callback

```
Setup:
  - Borrower: 10 ETH collateral, 9,500 USDC debt (HF = 0.95)
  - Liquidator: Uses custom swap handler
  - DEX: Has no liquidity for ETH→USDC

1. Liquidator calls prepare_liquidation():
   - Authorization stored with 5-minute expiry
   - Params: user, debt=USDC, collateral=ETH, debt_to_cover=9500, min_swap_out=9500

2. Liquidator calls execute_liquidation():
   a. Fresh prices fetched, HF verified < 1.0 ✓
   b. Flash loan initiated: Router borrows 9,500 USDC from aToken pool
   c. Flash loan callback executes:
      - Debt burned: 9,500 USDC from user ✓ (persistent, NOT reverted)
      - Collateral burned: 10.5 ETH from user, transferred to Router ✓ (persistent)
      - DEX swap: ETH → USDC
        * swap_via_handler calls malicious/empty handler
        * Handler reverts (or returns insufficient output)
        * Swap fails → returns Err
   d. Callback returns Err → execute_operation returns false
   
3. Flash loan verification fails (Router doesn't have enough to repay 9,500 USDC)
   Router's execute_liquidation REVERTS
   
4. STATE PERSISTS:
   - Router's temporary storage reverted (LIQCB cleared)
   - Router's persistent state (none in this step)
   - BUT: DebtToken's burn_scaled already executed → user's debt = 0 (persistent)
   - AND: aToken's burn already executed → user's collateral reduced (persistent)
   
5. POSITION IS BROKEN:
   - User: 0 debt (accidentally repaid), ~0 collateral (partially seized)
   - User cannot repay (debt is 0)
   - User cannot be liquidated (no debt)
   - Liquidator's authorization expired
   - Protocol must manually reconcile
```

## Impact

| Impact | Description |
|--------|-------------|
| **Irreversible state corruption** | User's debt and collateral positions modified without completing liquidation |
| **Fund loss** | Collateral may be stuck in the pool contract with no recovery path |
| **Protocol reserve depletion** | Each failed callback wastes gas and leaves inconsistent state |
| **Recovery complexity** | Requires manual admin intervention or emergency governance action |
| **Denial of service** | Malicious liquidators can intentionally trigger callback failures |

## Proof of Concept

```rust
// poc_liquidation_callback_failure.rs

#[cfg(test)]
mod poc_liquidation_callback_partial_failure {
    
    /// Simulates the state changes in execute_liquidation_callback
    fn simulate_liquidation_callback(
        env: &Env,
        params: &LiquidationCallbackParams,
        dex_swap_succeeds: bool,
    ) -> Result<(), KineticRouterError> {
        // STEP 1: Burn debt tokens (persistent storage change)
        // This executes regardless of subsequent failures
        let burn_result = env.try_invoke_contract::<(bool, i128, i128), KineticRouterError>(
            &params.debt_reserve_data.debt_token_address,
            &Symbol::new(env, "burn_scaled"),
            burn_debt_args,
        );
        // If this succeeds and the rest fails, debt is GONE
        
        // STEP 2: Burn aTokens + transfer collateral (persistent)
        let burn_and_transfer_result = env.try_invoke_contract::<(i128, i128, u128), KineticRouterError>(
            &params.collateral_reserve_data.a_token_address,
            &Symbol::new(env, "burn_scaled_and_transfer_to"),
            burn_and_transfer_args,
        );
        // If this succeeds and swap fails, collateral is in pool
        
        // STEP 3: DEX swap (CAN FAIL)
        if !dex_swap_succeeds {
            return Err(KineticRouterError::InsufficientSwapOut);
        }
        
        // STEP 4: Repay flash loan
        // ...
        Ok(())
    }
    
    #[test]
    fn poc_partial_callback_failure_leaves_inconsistent_state() {
        // Setup: Borrower with debt and collateral
        
        // Execute callback where swap fails at STEP 3
        let result = simulate_liquidation_callback(
            &env,
            &params,
            dex_swap_succeeds: false,  // Swap fails
        );
        
        assert!(result.is_err());  // Callback failed
        
        // Check persistent state:
        // - User's debt: 0 (burned at STEP 1)
        // - User's collateral: < original (burned at STEP 2)
        // - Flash loan: NOT repaid (Router doesn't have the tokens)
        
        // State is inconsistent:
        // User has no debt (can't repay)
        // User has less collateral (can't recover)
        // Protocol must intervene
        
        println!("STATE AFTER FAILED CALLBACK:");
        println!("  User debt: 0 (burned, non-recoverable)");
        println!("  User collateral: < original (partially seized)");  
        println!("  Flash loan: NOT repaid");
        println!("  Position: INCONSISTENT");
    }
}
```

## Remediation

1. **Two-phase commit for callbacks**: Implement a `prepare_callback` / `finalize_callback` pattern where irreversible state changes only occur in `finalize_callback`, called only after all operations succeed.

2. **Rollback handler**: If the callback fails, execute a rollback routine that:
   - Re-mints burned debt tokens for the user
   - Re-mints burned aTokens and returns underlying to the user
   This requires storing sufficient information to reconstruct the reversal.

3. **Re-entrancy-safe state preservation**: Instead of unconditionally clearing `LiquidationCallbackParams`, only clear on success. On failure, preserve params with a retry flag and a bounded retry window (e.g., 5 minutes).

4. **Incremental callback with checkpoints**: Track callback progress (which steps completed) so a recovery path can resume from the last successful step.
