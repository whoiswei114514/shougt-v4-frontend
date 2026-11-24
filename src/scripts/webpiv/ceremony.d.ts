import type { AuthorityDescriptor, BrowserPendingJob } from './browserCeremony';

export interface CeremonySecretRequest {
  kind: 'management' | 'pin';
  stage: 'generate' | 'sign' | 'install' | 'proof';
  name: string;
  scheme?: string;
}

export interface CeremonyConfirmRequest {
  stage: 'generate' | 'sign' | 'install';
  name: string;
  slot: string;
  real_name: string;
  roles: string[];
  message: string;
  issuer_descriptor?: AuthorityDescriptor | null;
}

export interface CeremonyOptions {
  chooseCard: (stage: 'generate' | 'sign' | 'install', selected: string | undefined, job: BrowserPendingJob) => Promise<{ id: string; name: string; channel: unknown }>;
  secret: (settings: CeremonySecretRequest) => Promise<string>;
  confirm: (settings: CeremonyConfirmRequest) => Promise<boolean>;
  chooseSlot: (state: { slot: string; next_slot: string }) => Promise<boolean>;
  progress?: (message: string) => void;
  storage?: Storage;
}

export class WebPivCeremony {
  constructor(options: CeremonyOptions);
  run(
    stage: 'generate' | 'sign' | 'install',
    job: BrowserPendingJob,
    options: {
      reader?: string;
      slot?: string;
      ca_slot?: string;
      algorithm?: string;
      management_algorithm?: string;
    },
    operationId: string,
  ): Promise<Record<string, any>>;
  finish(identifier: string): void;
}
