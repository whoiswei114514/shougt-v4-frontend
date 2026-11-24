export interface WebUsbCardRecord {
  id: string;
  name: string;
  transport: string;
  platform: string;
  source: string;
  state: 'ready' | 'unavailable' | 'disconnected' | 'fido_only' | 'unsupported' | string;
  piv: boolean;
  fido2: boolean;
  error?: string;
}

export class CardRegistry {
  supported(): boolean;
  enumerate(probe?: boolean, force?: boolean): Promise<WebUsbCardRecord[]>;
  requestDevice(): Promise<string>;
  channel(id: string): { id: string; name: string; channel: unknown };
}

export function createCardRegistry(): CardRegistry;
