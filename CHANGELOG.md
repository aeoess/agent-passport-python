# Changelog

## 2.5.0

### Added
- **`record_spend(commerce_delegation, amount)`** (`commerce.py`): the stateless write primitive for
  commerce spend. It returns a new CommerceDelegation with `spentAmount` incremented, refusing a
  non-finite or negative amount and refusing a spend that would exceed `spendLimit`. It pairs with the
  spend gate: check before a purchase, record after, persist the returned object. The SDK does not
  persist spend between calls; cumulative enforcement across purchases is the caller's or the gateway's
  responsibility. This is the parity primitive for the TypeScript `recordSpend`.

### Fixed / Security
- **Spend-accumulation no-op closed.** `spentAmount` was read by the spend check but never written, so a
  single delegation passed unlimited purchases against its cap. `record_spend` is the write half; the
  signed core delegation's `spentAmount` is documented as an immutable spend-at-issue value (always 0),
  not a running total.
- **`sub_delegate` now verifies the parent and narrows correctly** (`delegation.py`). It verifies the
  parent before minting a child, caps the child's expiry to the parent's, rejects a child whose spend
  exceeds the parent's remaining budget, and computes depth-exceeded rather than hardcoding it false.
- **`commerce_preflight` spend gate denies a currency mismatch** (`commerce.py`). The gate compared
  amounts without checking currency, so a purchase in one currency passed a budget denominated in
  another (the SDK does no conversion). A declared currency mismatch is now denied; an absent currency
  on either side stays unconstrained.

### Behavior changes (operations previously permitted now fail closed)
- A cross-currency commerce spend (purchase currency differs from the budget currency) is now denied
  instead of passing.
- A sub-delegation that widens authority (spend above the parent remaining, expiry beyond the parent,
  or depth past the limit) or that derives from a parent that does not verify is now rejected instead of
  produced.
