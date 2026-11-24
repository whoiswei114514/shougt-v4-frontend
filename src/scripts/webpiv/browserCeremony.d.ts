export interface AuthorityDescriptor {
  fingerprint: string;
  kind: 'ca_card' | 'super_admin_card' | 'superadmin_admin_card' | string;
  label: string;
  cn: string;
  owner_name: string;
  algorithm?: string;
  expires_at?: string;
  temporary_only: boolean;
  max_validity_days: number | null;
}

export interface BrowserCardDescriptor {
  reader: string;
  slot: string;
  algorithm: string;
  transport: string;
  protocol: string;
  platform: string;
  on_card_generation: boolean;
  browser_keystore?: boolean;
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
  self_service?: boolean;
  async_request?: boolean;
  requester_username?: string;
  format_version?: number;
  state: 'requested' | 'key_ready' | 'complete' | string;
  created_at?: string | null;
  csr_submitted_at?: string | null;
  expires_at: string;
  algorithms: string[];
  authorities: string[];
  authority_descriptors?: AuthorityDescriptor[];
  roots: string[];
  card?: BrowserCardDescriptor | null;
  csr_pem?: string | null;
  public_key_sha256?: string | null;
  signed_chain_pem?: string[] | null;
  has_target_csr: boolean;
  has_target_proof: boolean;
  issuer_kind?: string | null;
  issuer_label?: string | null;
  signed_by_name?: string | null;
  signed_at?: string | null;
}

export function findAuthorityDescriptor(
  job: BrowserPendingJob | null | undefined,
  fp: string,
): AuthorityDescriptor | null;
