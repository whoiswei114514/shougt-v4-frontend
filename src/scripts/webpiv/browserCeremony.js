export function findAuthorityDescriptor(job, fp) {
  return (job?.authority_descriptors || []).find(item => item.fingerprint === fp) || null;
}
