let capturedTicket: string | null = null;

function isImpersonationPath(pathname: string): boolean {
  return pathname.replace(/\/+$/, '') === '/security/impersonate';
}

export function scrubTicketFromLocation(): string | null {
  if (typeof window === 'undefined') return null;
  const rawHash = window.location.hash;
  if (!rawHash || rawHash.length <= 1) return null;
  const params = new URLSearchParams(rawHash.slice(1));
  if (!params.has('ticket')) return null;

  const ticket = params.get('ticket')?.trim() ?? '';
  params.delete('ticket');
  const remaining = params.toString();
  const cleanUrl =
    window.location.pathname +
    window.location.search +
    (remaining ? `#${remaining}` : '');
  try {
    window.history.replaceState(window.history.state, '', cleanUrl);
  } catch {
    window.location.hash = remaining ? `#${remaining}` : '';
  }

  if (ticket && isImpersonationPath(window.location.pathname)) {
    capturedTicket = ticket;
    return ticket;
  }
  return null;
}

export function consumeImpersonationTicket(): string | null {
  const fresh = scrubTicketFromLocation();
  const ticket = fresh || capturedTicket;
  capturedTicket = null;
  if (!ticket) return null;
  if (typeof window !== 'undefined' && !isImpersonationPath(window.location.pathname)) {
    return null;
  }
  return ticket;
}

export function clearCapturedImpersonationTicket(): void {
  capturedTicket = null;
}

scrubTicketFromLocation();
