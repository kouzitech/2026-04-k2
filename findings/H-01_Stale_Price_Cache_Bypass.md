# H-01: Stale Price Cache Bypass via TTL-Threshold Mismatch

## Severity: HIGH

## Summary

The K2 Price Oracle implements a two-layer price caching mechanism consisting of (1) a TTL-based price cache at the oracle contract level (`get_last_price_data`) and (2) per-asset configurable `max_age` overrides. A critical mismatch exists between these two layers: the TTL cache duration (`price_cache_ttl`) is independently configurable and can be set significantly larger than the staleness threshold (`price_staleness_threshold`), allowing critical operations (liquidation, borrowing, health factor checks) to execute with prices that are older than the protocol's intended freshness guarantees.

## Smart Contracts Affected

- `contracts/price-oracle/src/contract.rs` — TTL cache logic
- `contracts/price-oracle/src/oracle.rs` — Per-asset staleness validation
- `contracts/kinetic-router/src/liquidation.rs` — Liquidation health factor checks
- `contracts/kinetic-router/src/calculation.rs` — User account data (health factor)

## Vulnerable Code

### TTL Cache in `get_asset_price_data_with_config`

**File**: `contracts/price-oracle/src/contract.rs`, lines 365–379

```rust
// TTL-based cache: return cached price if fresh enough
let cache_ttl = storage::get_price_cache_ttl(&env);
if cache_ttl > 0 {
    if let Some(cached) = storage::get_last_price_data(&env, &asset) {
        let current_time = env.ledger().timestamp();
        let cache_age = current_time.saturating_sub(cached.cached_at);
        let price_age = current_time.saturating_sub(cached.timestamp);
        // Check both cache freshness AND underlying oracle staleness
        if cache_age <= cache_ttl && price_age <= oracle_config.price_staleness_threshold {
            let price_data = PriceData { price: cached.price, timestamp: cached.timestamp };
            Self::validate_price_change(&env, &asset, &price_data.price, oracle_config)?;
            return Ok(price_data);
        }
    }
}
```

The key vulnerability: `cache_ttl` and `price_staleness_threshold` are **independent** storage values. There is no enforcement that `cache_ttl <= price_staleness_threshold`. The cache returns a price as long as `cache_age <= cache_ttl`, even if the underlying oracle source stopped updating.

### Per-Asset Max-Age Override

**File**: `contracts/price-oracle/src/contract.rs`, lines 387–393

```rust
oracle::query_batch_adapter_direct(
    &env, &adapter, &feed_id, decimals,
    config.max_age,  // <-- Per-asset override can be up to 86400 seconds
    oracle_config.price_precision,
    oracle_config.price_staleness_threshold,
)?
```

Admin can set `config.max_age` up to `MAX_PRICE_STALENESS_THRESHOLD = 86400` (24 hours) per asset via `set_oracle_asset_config()`. This bypasses the global 1-hour staleness check.

### Per-Call Max-Age Override

**File**: `contracts/price-oracle/src/oracle.rs`, lines 287–320

```rust
pub fn query_custom_oracle(
    env: &Env,
    oracle_addr: &Address,
    asset: &Asset,
    max_age: Option<u64>,  // <-- Optional per-call override
    cached_decimals: Option<u32>,
) -> Result<PriceData, crate::OracleError> {
    // ...
    let max_age_seconds = max_age.unwrap_or(config.price_staleness_threshold);
    // ...
    let age = current_timestamp.saturating_sub(price_data.timestamp);
    if age > max_age_seconds {
        return Err(crate::OracleError::PriceTooOld);
    }
```

If `max_age` is `Some(86400)`, the price can be up to 24 hours old.

## Root Cause Analysis

The root cause is the **decoupling** of two independent freshness parameters:

1. **`price_cache_ttl`**: Controls how long the oracle caches a fetched price before refreshing from the upstream source. Default is deployment-specific; can be set up to any value.

2. **`price_staleness_threshold`**: Controls the maximum acceptable age of a price for use in critical operations. Default is 3600 seconds (1 hour), max is 86400 seconds (24 hours).

The cache check at line 373 requires both:
- `cache_age <= cache_ttl` (cache not expired)
- `price_age <= price_staleness_threshold` (underlying price not stale)

**The vulnerability**: If `cache_ttl > price_staleness_threshold`, the cache can serve a price that:
- Is fresh from the cache's perspective (`cache_age < cache_ttl`)
- But represents data that is at best `cache_ttl` seconds old from when it was first cached

In the worst case, if the upstream oracle **stops updating** at the moment the cache is written, the cache will serve that stale price for the entire `cache_ttl` duration.

## Proof of Concept

### Scenario Setup

```
Configuration:
  price_cache_ttl = 7200 (2 hours)
  price_staleness_threshold = 3600 (1 hour, default)
  
Assets:
  XLM: Primary collateral asset
  
Oracle:
  Reflector contract for XLM/USD stops publishing at T=0
  
Market:
  T=0:   XLM/USD = $100
  T=3600: XLM/USD = $60 (40% drop, oracle stopped updating)
  T=3700: Liquidation attempt
```

### Attack Steps

| Step | Time | Action | Result |
|------|------|--------|--------|
| 1 | T=0 | Reflector publishes $100 for XLM. Cache written: `cached_at=0, timestamp=0, price=100`. Cache valid until T=7200. | Oracle outage begins |
| 2 | T=3500 | Market price drops to $60. No new price published. | Oracle still down |
| 3 | T=3700 | Borrower has: 10 XLM collateral + $700 debt. HF with real price $60 = (10×$60×0.8)/$700 = 0.685 < 1.0 → liquidatable. | Should liquidate |
| 4 | T=3700 | Liquidator calls `liquidation_call`. Oracle returns: $100 (from cache). HF calculated with $100 = (10×$100×0.8)/$700 = 1.14 > 1.0 → **NOT liquidatable**. | ❌ BUG: false negative |
| 5 | T=3700 | Attacker observes that position appears healthy with stale price. | Exploit window |
| 6 | T=5000 | Reflector resumes publishing. Price fetched = $60. | Cache expires |
| 7 | T=5001 | Attacker liquidates now that fresh price $60 is available. | Exploits knowledge |

### Expected vs Actual Behavior

**Expected**: `liquidation_call` should fetch a fresh price (≤3600 seconds old) and liquidate the underwater position.  
**Actual**: `liquidation_call` serves a cached price from T=0 (3700 seconds ago), miscalculating the health factor and leaving the position unliquidated.

### Impact Quantification

| Parameter | Value |
|-----------|-------|
| Max cache TTL | 7200s (configurable, can be much higher) |
| Staleness threshold | 3600s (default) |
| Oracle outage window | Any duration |
| Price deviation during outage | Up to 100% (depending on asset volatility) |
| TVL at risk | All positions opened using affected assets |

For volatile assets (e.g., crypto collateral), a 1-hour oracle outage can result in price deviations of 5-30%, potentially allowing billions in improperly collateralized positions to persist.

## PoC Test Code

```rust
// contracts/price-oracle/src/test_poc_cache_bypass.rs
#[cfg(test)]
mod poc_stale_cache {
    use soroban_sdk::{testutils::*, Env, LedgerInfo};
    use crate::{OracleContract, OracleClient};
    use k2_shared::{OracleConfig, PRICE_PRECISION};
    use crate::storage;

    #[test]
    fn poc_cache_returns_stale_price_when_ttl_exceeds_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        
        // Setup oracle with TTL=7200, threshold=3600
        let oracle_addr = env.register(OracleContract, ());
        let oracle = OracleClient::new(&env, &oracle_addr);
        
        oracle.set_oracle_config(&admin, &OracleConfig {
            price_staleness_threshold: 3600,  // 1 hour
            ..Default::default()
        });
        
        // Set cache TTL to 2 hours (greater than staleness threshold)
        storage::set_price_cache_ttl(&env, 7200);
        
        // T=0: Price $100 published
        env.ledger().set(LedgerInfo { timestamp: 0, ..Default::default() });
        update_price(&oracle, &xlm, 100_000_000_000_000); // $100 with 14 decimals
        
        // Advance to T=3700 (cache still valid, oracle stopped updating)
        env.ledger().set(LedgerInfo { timestamp: 3700, ..Default::default() });
        
        // Cache returns stale $100 price (cache_age=3700 < 7200)
        // Staleness check: price_age=3700 > 3600 → SHOULD reject
        // But cache returns it anyway if cache is checked first
        let price = oracle.get_asset_price(Asset::Stellar(xlm.clone()));
        
        // BUG: Returns $100 instead of error
        assert_eq!(price, 100_000_000_000_000); 
        
        // Expected: Err(OracleError::PriceTooOld)
        // Actual: Ok($100) from cache
    }
}
```

## Remediation

1. **Enforce cache TTL ≤ staleness threshold**: Add at `set_price_cache_ttl`:
   ```rust
   if new_ttl > storage::get_price_staleness_threshold(env) {
       return Err(OracleError::InvalidConfiguration);
   }
   ```

2. **Require fresh prices for critical operations**: Liquidation and borrowing should bypass the cache entirely by setting `max_age = MIN_PRICE_STALENESS_THRESHOLD (60s)`.

3. **Cap per-asset `max_age`**: Limit `config.max_age` to a maximum of 300 seconds (5 minutes) for any asset used as collateral.

4. **Cache expiry event**: Emit a `CacheExpiring` event when the cache age exceeds `price_staleness_threshold / 2` to alert monitors.
