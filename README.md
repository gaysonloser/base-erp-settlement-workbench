# Base ERP Settlement Workbench

This project ports the CIRCLE Arc-to-ERP V3.2 settlement workbench into a Base-native product. The frozen upstream snapshot is retained under `upstream/arc_erp_v3_2/`; it is evidence and reusable implementation material, not a Base truth source.

Current local validation (`2026-08-10` 02_Build revalidation): `55 total / 55 pass`; all six B08 preflight/runtime-authority drift checks and all seven B11 business-closure evidence checks pass against the live 2026-08-10 daily runtime. This is local evidence only and grants no wallet, ERP mutation, publication or execution authority.

The B08 revalidation adds `readCurrentBaseRuntimeBinding` as the canonical source of the current 02_Build runtime hash, run id, date and cursor. The release candidate is recorded in `runtime/release_candidate_2026-08-10.json`; its eight-platform and chain receipts remain unobserved, so it is not a publication unit or daily count.

## Product boundary

The product closes a receipt-first operating loop:

`Base event -> settlement case -> evidence match -> ERP draft/posting -> ledger/close readback -> ecosystem proof`

Base-specific lanes are Smart Wallet receivable/payable/refund, x402 API settlement, B20 inventory/role lifecycle, programmable contract settlement, treasury swap reconciliation, and agentic workflow evidence. A standard transfer proves only a transfer. Invoice, counterparty, refund and accounting meaning require separate business evidence and fail closed when ambiguous.

## Session ownership

- `03_Base` is the product/knowledge owner analogous to CIRCLE `14_Arc`: maintain scenario truth, Base official-source mapping, product queue, tests, quality review and a typed handoff. It has no wallet-write or external-publication authority.
- `02_Build` is the engineering/execution owner analogous to CIRCLE `09_Circle`: implement the accepted packet, run ERP/Frappe integration, execute owner-reviewed Smart Wallet actions and publish truthful receipts. Its existing daily runtime remains the only authority for `30+10`.
- `01_Config` owns registry, scope separation, audits and source-snapshot integrity.

The only product exchange is `shared/base_erp_exchange_v1.json`. Daily chain counts, wallet gates and publication counters never enter this project runtime.

## Source and implementation

- Upstream manifest: `config/upstream_arc_source_manifest.json`
- Base product contract: `config/base_erp_product_contract_v1.json`
- Product runtime: `runtime/current_state.json`
- Base scenario router: `src/base-erp-scenario-router.mjs`
- Tests: `test/base-erp-scenario-router.test.mjs`
- Simulation schema and fixture: `config/simulated_transaction_record_schema.json`, `fixtures/simulated_transactions.json`
- Public identity/exposure contract: `config/release_identity_and_exposure_contract_v1.json`
- Mutable Arc upstream delta contract: `config/arc_upstream_sync_contract_v1.json`

The upstream snapshot deliberately excludes `.git`, `node_modules`, caches and historical review artifacts. Arc chain/network/wallet claims must be replaced with current Base official facts before promotion. B20 experimentation starts on Base Vibenet; Base Sepolia is used for ordinary testnet product flows; Base Mainnet actions require the existing `02_Build` single-review gate.

## Delivery standard

Local tests and simulation are L0/L1 evidence only. L2 needs a unique successful testnet receipt plus deterministic product readback. L3 needs a unique Base Mainnet Smart Wallet receipt, authoritative ERP readback, same-commit Git/Render proof and the required Base ecosystem receipts. No platform row or simulated ERP record may be promoted into a daily count by prose.

Every simulated transaction is structurally non-countable: it has no transaction hash, is marked `not_broadcast`, and remains L0. Simulation records support product and ERP construction only; the existing `02_Build` runtime owns all real daily counts.

Every truthful public release must expose `gaysonloser.base.eth` together with the full primary Base Account `0xBa36D092dB2999bb1FaBbaf281AC956A97189C25`, the release fingerprint and evidence limitations. Basename resolution, Builder Code attribution, platform verification, transaction success and score movement are independently verified claims; configuration alone cannot prove them.

The Arc ERP source remains a moving upstream. BASE never silently recopies its dirty working tree. `03_Base` reviews semantic deltas into the single project exchange, and `02_Build` implements only accepted, Base-revalidated packets.
