const INFRA_SUFFIXES = [
  'dns-filter', 'http-proxy', 'mitm-proxy', 'email-proxy', 'warden', 'log-shipper', 'log-store',
];

export const isInfraContainer = (name: string) =>
  INFRA_SUFFIXES.some((s) => name === s || name.endsWith(`-${s}`));
