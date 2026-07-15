export type MajikChainAnchorMemo = string;
export type MajikChainAnchorTxSignature = string;

export interface MajikChainAnchorPayload {
  chain: string; // e.g. "solana" — plain string, not a literal union: majik-signature
  network: string; // stays chain-agnostic and never needs updating to add a second chain.
  digest: {
    algorithm: "SHA3-512";
    /** Hex-encoded, 128 chars — sourced as-is from getSealInfo().sealHash, no re-encoding */
    value: string; //
  };
}

export interface MajikChainAnchor {
  version: 1;
  id: string; // internal UUID, matches chain_anchors.id
  payload: MajikChainAnchorPayload;
  memo: MajikChainAnchorMemo; // exact string written on-chain: "majik-notary-v1:{sealHash}"
  txSignature: MajikChainAnchorTxSignature; // base58
  slot: number | null; // null until confirmed
  blockTime: number | null; // Unix seconds, null until confirmed
  confirmedAt: string | null; // ISO 8601, set when status first reaches "confirmed"
  status: "pending" | "confirmed" | "finalized" | "failed";
}
