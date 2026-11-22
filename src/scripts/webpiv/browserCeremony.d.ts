export interface BrowserCardDescriptor {
  reader: string;
  slot: string;
  algorithm: string;
  transport: string;
  protocol: string;
  platform: string;
  on_card_generation: boolean;
  browser_keystore: boolean;
}

export interface BrowserPendingJob {
  issuance_id: string;
  nonce: string;
  write_nonce?: string | null;
  user_id: number;
  user_version: number;
  real_name: string;
  roles: string[];
  temporary: boolean;
  validity_days?: number | null;
  delegated_ca: boolean;
  state: 'requested' | 'key_ready' | 'complete' | string;
  expires_at: string;
  algorithms: string[];
  authorities: string[];
  roots: string[];
  card?: BrowserCardDescriptor | null;
  public_key_sha256?: string | null;
  signed_chain_pem?: string[] | null;
  has_target_csr: boolean;
  has_target_proof: boolean;
}

export interface BrowserCaEntry {
  fingerprint: string;
  cn: string;
  label?: string;
  algorithm: string;
  expires_at: string;
  saved_at: string;
}

export function generateBrowserKey(params: {
  job: BrowserPendingJob;
  passphrase: string;
  algorithm?: string;
}): Promise<{
  issuance_id: string;
  csr_pem: string;
  card: BrowserCardDescriptor;
}>;

export function installBrowserCert(params: {
  job: BrowserPendingJob & { chain_pem?: string[] };
  passphrase: string;
  saveToCaVault?: boolean;
  friendlyName?: string;
}): Promise<{
  p12Bytes: Uint8Array;
  filename: string;
  isCaCert: boolean;
  receipt: {
    issuance_id: string;
    chain_pem: string[];
    proof: string;
    readback_verified: boolean;
    onsite_confirmed: boolean;
    card_slot: string;
  };
}>;

export function signWithBrowserCa(params: {
  job: BrowserPendingJob;
  p12Bytes?: Uint8Array | null;
  fingerprint?: string;
  passphrase: string;
}): Promise<BrowserPendingJob & { issuer_slot: string; chain_pem: string[] }>;

export function importCaPkcs12ToVault(params: {
  p12Bytes: Uint8Array;
  passphrase: string;
  label?: string;
}): Promise<{ fingerprint: string; cn: string; algorithm: string; expires_at: string }>;

export function listCaEntries(): Promise<BrowserCaEntry[]>;
export function removeCaEntry(fingerprint: string): Promise<void>;
export function hasPendingKey(issuanceId: string): Promise<boolean>;
export function deletePendingKey(issuanceId: string): Promise<void>;
