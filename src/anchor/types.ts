/** Versioned memo string committed to the external chain. */
export type MajikChainAnchorMemo = string;
/** Transaction identifier returned by the chain network. */
export type MajikChainAnchorTxSignature = string;

/** Chain-neutral description of the seal digest being anchored. */
export interface MajikChainAnchorPayload {
  chain: string; // e.g. "solana" — plain string, not a literal union: majik-signature
  network: string; // stays chain-agnostic and never needs updating to add a second chain.
  digest: {
    algorithm: "SHA3-512";
    /** Hex-encoded, 128 chars — sourced as-is from getSealInfo().sealHash, no re-encoding */
    value: string; //
  };
}

/** Stored record of an externally confirmed chain anchor for an envelope seal. */
export interface MajikChainAnchor {
  version: 1;
  id: string; // internal UUID, matches chain_anchors.id
  payload: MajikChainAnchorPayload;
  memo: MajikChainAnchorMemo; // exact string written on-chain: "majik-notary-v-1:{sealHash}"
  txSignature: MajikChainAnchorTxSignature; // base58
  slot: number | null; // null until confirmed
  blockTime: number | null; // Unix seconds, null until confirmed
  confirmedAt: string | null; // ISO 8601, set when status first reaches "confirmed"
  status: "pending" | "confirmed" | "finalized" | "failed";
}
