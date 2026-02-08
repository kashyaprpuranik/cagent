import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Save,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Plus,
  Trash2,
  Edit2,
  Globe,
  Settings,
  Code,
  X,
  Shield,
  Clock,
  Gauge,
  Key,
} from 'lucide-react';
import { getConfig, updateConfigRaw, reloadConfig, Config, DomainEntry } from '../api/client';

type Tab = 'domains' | 'settings' | 'raw';

interface ValidationError {
  field: string;
  message: string;
}

// Validation functions
function validateDomain(domain: string): string | null {
  if (!domain) return 'Domain is required';
  // Allow wildcards like *.example.com or plain domains
  const pattern = /^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  if (!pattern.test(domain)) {
    return 'Invalid domain format (e.g., example.com or *.example.com)';
  }
  return null;
}

function validateAlias(alias: string): string | null {
  if (!alias) return null; // Optional
  const pattern = /^[a-zA-Z0-9-]+$/;
  if (!pattern.test(alias)) {
    return 'Alias must be alphanumeric with hyphens only';
  }
  return null;
}

function validateTimeout(timeout: string): string | null {
  if (!timeout) return null; // Optional
  const pattern = /^\d+[smh]?$/;
  if (!pattern.test(timeout)) {
    return 'Invalid timeout (e.g., 30s, 5m, 1h)';
  }
  return null;
}

function validatePositiveInt(value: number | undefined, fieldName: string): string | null {
  if (value === undefined) return null;
  if (!Number.isInteger(value) || value <= 0) {
    return `${fieldName} must be a positive integer`;
  }
  return null;
}

// Domain Editor Modal
function DomainModal({
  domain,
  onSave,
  onClose,
  existingDomains,
}: {
  domain: DomainEntry | null;
  onSave: (domain: DomainEntry) => void;
  onClose: () => void;
  existingDomains: string[];
}) {
  const [form, setForm] = useState<DomainEntry>(
    domain || { domain: '' }
  );
  const [errors, setErrors] = useState<ValidationError[]>([]);
  const [showCredential, setShowCredential] = useState(!!domain?.credential);
  const [showRateLimit, setShowRateLimit] = useState(!!domain?.rate_limit);

  const validate = (): boolean => {
    const newErrors: ValidationError[] = [];

    const domainErr = validateDomain(form.domain);
    if (domainErr) newErrors.push({ field: 'domain', message: domainErr });

    // Check for duplicate domain (only if adding new or changing domain name)
    if (!domain || domain.domain !== form.domain) {
      if (existingDomains.includes(form.domain)) {
        newErrors.push({ field: 'domain', message: 'Domain already exists' });
      }
    }

    const aliasErr = validateAlias(form.alias || '');
    if (aliasErr) newErrors.push({ field: 'alias', message: aliasErr });

    const timeoutErr = validateTimeout(form.timeout || '');
    if (timeoutErr) newErrors.push({ field: 'timeout', message: timeoutErr });

    if (showRateLimit && form.rate_limit) {
      const rpmErr = validatePositiveInt(form.rate_limit.requests_per_minute, 'Requests/min');
      if (rpmErr) newErrors.push({ field: 'rate_limit.requests_per_minute', message: rpmErr });

      const burstErr = validatePositiveInt(form.rate_limit.burst_size, 'Burst size');
      if (burstErr) newErrors.push({ field: 'rate_limit.burst_size', message: burstErr });
    }

    if (showCredential && form.credential) {
      if (!form.credential.header) {
        newErrors.push({ field: 'credential.header', message: 'Header name is required' });
      }
      if (!form.credential.env) {
        newErrors.push({ field: 'credential.env', message: 'Environment variable is required' });
      }
    }

    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleSave = () => {
    if (!validate()) return;

    const cleanedForm: DomainEntry = { domain: form.domain };

    if (form.alias) cleanedForm.alias = form.alias;
    if (form.timeout) cleanedForm.timeout = form.timeout;
    if (form.read_only) cleanedForm.read_only = form.read_only;

    if (showRateLimit && form.rate_limit?.requests_per_minute) {
      cleanedForm.rate_limit = {
        requests_per_minute: form.rate_limit.requests_per_minute,
        burst_size: form.rate_limit.burst_size || 10,
      };
    }

    if (showCredential && form.credential?.header && form.credential?.env) {
      cleanedForm.credential = {
        header: form.credential.header,
        format: form.credential.format || '{value}',
        env: form.credential.env,
      };
    }

    onSave(cleanedForm);
  };

  const getError = (field: string) => errors.find((e) => e.field === field)?.message;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 border border-gray-700 rounded-lg w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">
            {domain ? 'Edit Domain' : 'Add Domain'}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Domain */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Domain <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.domain}
              onChange={(e) => setForm({ ...form, domain: e.target.value })}
              placeholder="api.example.com or *.example.com"
              className={`w-full bg-gray-900 border rounded px-3 py-2 text-white focus:outline-none ${
                getError('domain') ? 'border-red-500' : 'border-gray-600 focus:border-blue-500'
              }`}
            />
            {getError('domain') && (
              <p className="text-red-400 text-xs mt-1">{getError('domain')}</p>
            )}
          </div>

          {/* Alias */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Alias <span className="text-gray-500">(optional)</span>
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={form.alias || ''}
                onChange={(e) => setForm({ ...form, alias: e.target.value || undefined })}
                placeholder="shortname"
                className={`flex-1 bg-gray-900 border rounded px-3 py-2 text-white focus:outline-none ${
                  getError('alias') ? 'border-red-500' : 'border-gray-600 focus:border-blue-500'
                }`}
              />
              <span className="text-gray-500 text-sm">.devbox.local</span>
            </div>
            {getError('alias') && (
              <p className="text-red-400 text-xs mt-1">{getError('alias')}</p>
            )}
          </div>

          {/* Timeout */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Timeout <span className="text-gray-500">(optional)</span>
            </label>
            <input
              type="text"
              value={form.timeout || ''}
              onChange={(e) => setForm({ ...form, timeout: e.target.value || undefined })}
              placeholder="30s"
              className={`w-full bg-gray-900 border rounded px-3 py-2 text-white focus:outline-none ${
                getError('timeout') ? 'border-red-500' : 'border-gray-600 focus:border-blue-500'
              }`}
            />
            {getError('timeout') && (
              <p className="text-red-400 text-xs mt-1">{getError('timeout')}</p>
            )}
          </div>

          {/* Read Only */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="read_only"
              checked={form.read_only || false}
              onChange={(e) => setForm({ ...form, read_only: e.target.checked || undefined })}
              className="w-4 h-4 rounded bg-gray-900 border-gray-600"
            />
            <label htmlFor="read_only" className="text-sm text-gray-300">
              Read-only (block POST/PUT/DELETE)
            </label>
          </div>

          {/* Rate Limit Toggle */}
          <div className="border-t border-gray-700 pt-4">
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm text-gray-300 flex items-center gap-2">
                <Gauge className="w-4 h-4" />
                Rate Limit
              </label>
              <button
                type="button"
                onClick={() => {
                  setShowRateLimit(!showRateLimit);
                  if (!showRateLimit) {
                    setForm({
                      ...form,
                      rate_limit: { requests_per_minute: 60, burst_size: 10 },
                    });
                  } else {
                    setForm({ ...form, rate_limit: undefined });
                  }
                }}
                className={`px-2 py-1 text-xs rounded ${
                  showRateLimit ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'
                }`}
              >
                {showRateLimit ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            {showRateLimit && (
              <div className="grid grid-cols-2 gap-3 mt-2">
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Requests/min</label>
                  <input
                    type="number"
                    value={form.rate_limit?.requests_per_minute || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        rate_limit: {
                          ...form.rate_limit,
                          requests_per_minute: parseInt(e.target.value) || 0,
                          burst_size: form.rate_limit?.burst_size || 10,
                        },
                      })
                    }
                    className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Burst size</label>
                  <input
                    type="number"
                    value={form.rate_limit?.burst_size || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        rate_limit: {
                          ...form.rate_limit,
                          requests_per_minute: form.rate_limit?.requests_per_minute || 60,
                          burst_size: parseInt(e.target.value) || 0,
                        },
                      })
                    }
                    className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Credential Toggle */}
          <div className="border-t border-gray-700 pt-4">
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm text-gray-300 flex items-center gap-2">
                <Key className="w-4 h-4" />
                Credential Injection
              </label>
              <button
                type="button"
                onClick={() => {
                  setShowCredential(!showCredential);
                  if (!showCredential) {
                    setForm({
                      ...form,
                      credential: { header: 'Authorization', format: 'Bearer {value}', env: '' },
                    });
                  } else {
                    setForm({ ...form, credential: undefined });
                  }
                }}
                className={`px-2 py-1 text-xs rounded ${
                  showCredential ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'
                }`}
              >
                {showCredential ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            {showCredential && (
              <div className="space-y-3 mt-2">
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Header Name</label>
                  <input
                    type="text"
                    value={form.credential?.header || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        credential: { ...form.credential!, header: e.target.value },
                      })
                    }
                    placeholder="Authorization"
                    className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Format</label>
                  <input
                    type="text"
                    value={form.credential?.format || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        credential: { ...form.credential!, format: e.target.value },
                      })
                    }
                    placeholder="Bearer {value}"
                    className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  />
                  <p className="text-xs text-gray-500 mt-1">Use {'{value}'} as placeholder</p>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">Environment Variable</label>
                  <input
                    type="text"
                    value={form.credential?.env || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        credential: { ...form.credential!, env: e.target.value },
                      })
                    }
                    placeholder="API_KEY"
                    className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white text-sm"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="flex justify-end gap-2 p-4 border-t border-gray-700">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded"
          >
            {domain ? 'Update' : 'Add'} Domain
          </button>
        </div>
      </div>
    </div>
  );
}

// Settings Editor
function SettingsEditor({
  config,
  onChange,
}: {
  config: Config;
  onChange: (config: Config) => void;
}) {
  return (
    <div className="space-y-6">
      {/* DNS Settings */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Globe className="w-5 h-5 text-blue-400" />
          DNS Settings
        </h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Upstream DNS Servers</label>
            <input
              type="text"
              value={config.dns?.upstream?.join(', ') || '8.8.8.8, 8.8.4.4'}
              onChange={(e) =>
                onChange({
                  ...config,
                  dns: {
                    ...config.dns,
                    upstream: e.target.value.split(',').map((s) => s.trim()),
                    cache_ttl: config.dns?.cache_ttl || 300,
                  },
                })
              }
              placeholder="8.8.8.8, 8.8.4.4"
              className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white"
            />
            <p className="text-xs text-gray-500 mt-1">Comma-separated list of DNS servers</p>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Cache TTL (seconds)</label>
            <input
              type="number"
              value={config.dns?.cache_ttl || 300}
              onChange={(e) =>
                onChange({
                  ...config,
                  dns: {
                    ...config.dns,
                    upstream: config.dns?.upstream || ['8.8.8.8', '8.8.4.4'],
                    cache_ttl: parseInt(e.target.value) || 300,
                  },
                })
              }
              className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white"
            />
          </div>
        </div>
      </div>

      {/* Rate Limits */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Gauge className="w-5 h-5 text-yellow-400" />
          Default Rate Limits
        </h3>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Requests per Minute</label>
            <input
              type="number"
              value={config.rate_limits?.default?.requests_per_minute || 120}
              onChange={(e) =>
                onChange({
                  ...config,
                  rate_limits: {
                    default: {
                      requests_per_minute: parseInt(e.target.value) || 120,
                      burst_size: config.rate_limits?.default?.burst_size || 20,
                    },
                  },
                })
              }
              className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Burst Size</label>
            <input
              type="number"
              value={config.rate_limits?.default?.burst_size || 20}
              onChange={(e) =>
                onChange({
                  ...config,
                  rate_limits: {
                    default: {
                      requests_per_minute: config.rate_limits?.default?.requests_per_minute || 120,
                      burst_size: parseInt(e.target.value) || 20,
                    },
                  },
                })
              }
              className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white"
            />
          </div>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          Applied to domains without specific rate limits
        </p>
      </div>

      {/* Mode */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Settings className="w-5 h-5 text-gray-400" />
          Operation Mode
        </h3>

        <select
          value={config.mode || 'standalone'}
          onChange={(e) => onChange({ ...config, mode: e.target.value })}
          className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white"
        >
          <option value="standalone">Standalone (local config only)</option>
          <option value="connected">Connected (sync from control plane)</option>
        </select>
      </div>
    </div>
  );
}

export default function ConfigPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<Tab>('domains');
  const [rawContent, setRawContent] = useState('');
  const [config, setConfig] = useState<Config>({});
  const [hasChanges, setHasChanges] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [editingDomain, setEditingDomain] = useState<DomainEntry | null>(null);
  const [showDomainModal, setShowDomainModal] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ['config'],
    queryFn: getConfig,
  });

  useEffect(() => {
    if (data) {
      setRawContent(data.raw);
      setConfig(data.config);
      setHasChanges(false);
    }
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: updateConfigRaw,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
      setHasChanges(false);
      setSaveMessage({ type: 'success', text: 'Configuration saved' });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (err) => {
      setSaveMessage({ type: 'error', text: (err as Error).message });
    },
  });

  const reloadMutation = useMutation({
    mutationFn: reloadConfig,
    onSuccess: (result) => {
      setSaveMessage({
        type: 'success',
        text: `Config reloaded: ${Object.entries(result.results)
          .map(([k, v]) => `${k}: ${v}`)
          .join(', ')}`,
      });
      setTimeout(() => setSaveMessage(null), 5000);
    },
    onError: (err) => {
      setSaveMessage({ type: 'error', text: (err as Error).message });
    },
  });

  // Convert config to YAML-like string for saving
  const configToYaml = (cfg: Config): string => {
    const lines: string[] = [
      '# Cagent Data Plane Configuration',
      '',
      `mode: ${cfg.mode || 'standalone'}`,
      '',
      'dns:',
      '  upstream:',
      ...(cfg.dns?.upstream || ['8.8.8.8', '8.8.4.4']).map((s) => `    - ${s}`),
      `  cache_ttl: ${cfg.dns?.cache_ttl || 300}`,
      '',
      'rate_limits:',
      '  default:',
      `    requests_per_minute: ${cfg.rate_limits?.default?.requests_per_minute || 120}`,
      `    burst_size: ${cfg.rate_limits?.default?.burst_size || 20}`,
      '',
      'domains:',
    ];

    for (const domain of cfg.domains || []) {
      lines.push(`  - domain: ${domain.domain}`);
      if (domain.alias) lines.push(`    alias: ${domain.alias}`);
      if (domain.timeout) lines.push(`    timeout: ${domain.timeout}`);
      if (domain.read_only) lines.push(`    read_only: true`);
      if (domain.rate_limit) {
        lines.push('    rate_limit:');
        lines.push(`      requests_per_minute: ${domain.rate_limit.requests_per_minute}`);
        lines.push(`      burst_size: ${domain.rate_limit.burst_size}`);
      }
      if (domain.credential) {
        lines.push('    credential:');
        lines.push(`      header: ${domain.credential.header}`);
        lines.push(`      format: "${domain.credential.format}"`);
        lines.push(`      env: ${domain.credential.env}`);
      }
    }

    if (cfg.internal_services?.length) {
      lines.push('');
      lines.push('internal_services:');
      for (const svc of cfg.internal_services) {
        lines.push(`  - ${svc}`);
      }
    }

    return lines.join('\n') + '\n';
  };

  const handleSave = () => {
    if (activeTab === 'raw') {
      saveMutation.mutate(rawContent);
    } else {
      const yaml = configToYaml(config);
      saveMutation.mutate(yaml);
    }
  };

  const handleAddDomain = (domain: DomainEntry) => {
    if (editingDomain) {
      // Update existing
      setConfig({
        ...config,
        domains: config.domains?.map((d) =>
          d.domain === editingDomain.domain ? domain : d
        ),
      });
    } else {
      // Add new
      setConfig({
        ...config,
        domains: [...(config.domains || []), domain],
      });
    }
    setHasChanges(true);
    setShowDomainModal(false);
    setEditingDomain(null);
  };

  const handleDeleteDomain = (domainName: string) => {
    if (!confirm(`Delete domain "${domainName}"?`)) return;
    setConfig({
      ...config,
      domains: config.domains?.filter((d) => d.domain !== domainName),
    });
    setHasChanges(true);
  };

  const handleSettingsChange = (newConfig: Config) => {
    setConfig(newConfig);
    setHasChanges(true);
  };

  const handleRawChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setRawContent(e.target.value);
    setHasChanges(e.target.value !== data?.raw);
    setSaveMessage(null);
  };

  if (isLoading) {
    return <div className="text-gray-400">Loading configuration...</div>;
  }

  if (error) {
    return (
      <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-lg">
        Error loading config: {(error as Error).message}
      </div>
    );
  }

  const tabs = [
    { id: 'domains' as Tab, label: 'Domains', icon: Globe, count: config.domains?.length },
    { id: 'settings' as Tab, label: 'Settings', icon: Settings },
    { id: 'raw' as Tab, label: 'Raw YAML', icon: Code },
  ];

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Configuration</h1>
          <p className="text-sm text-gray-400 mt-1">
            {data?.path} • Last modified:{' '}
            {data?.modified ? new Date(data.modified).toLocaleString() : 'unknown'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${reloadMutation.isPending ? 'animate-spin' : ''}`} />
            Apply & Reload
          </button>
          <button
            onClick={handleSave}
            disabled={!hasChanges || saveMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            Save
          </button>
        </div>
      </div>

      {saveMessage && (
        <div
          className={`flex items-center gap-2 p-3 rounded-lg mb-4 ${
            saveMessage.type === 'success'
              ? 'bg-green-900/50 border border-green-700 text-green-300'
              : 'bg-red-900/50 border border-red-700 text-red-300'
          }`}
        >
          {saveMessage.type === 'success' ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            <AlertCircle className="w-4 h-4" />
          )}
          {saveMessage.text}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-gray-700">
        {tabs.map(({ id, label, icon: Icon, count }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
              activeTab === id
                ? 'border-blue-500 text-white'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
            {count !== undefined && (
              <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded">{count}</span>
            )}
          </button>
        ))}
      </div>

      {hasChanges && (
        <div className="mb-4 text-sm text-yellow-400 flex items-center gap-2">
          <AlertCircle className="w-4 h-4" />
          You have unsaved changes
        </div>
      )}

      {/* Tab Content */}
      <div className="flex-1 min-h-0 overflow-auto">
        {activeTab === 'domains' && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <p className="text-gray-400 text-sm">
                Allowed domains that the agent can access through the proxy
              </p>
              <button
                onClick={() => {
                  setEditingDomain(null);
                  setShowDomainModal(true);
                }}
                className="flex items-center gap-2 px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
              >
                <Plus className="w-4 h-4" />
                Add Domain
              </button>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700 text-left text-sm text-gray-400">
                    <th className="px-4 py-3">Domain</th>
                    <th className="px-4 py-3">Alias</th>
                    <th className="px-4 py-3">Options</th>
                    <th className="px-4 py-3 w-24">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(config.domains || []).map((domain) => (
                    <tr
                      key={domain.domain}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30"
                    >
                      <td className="px-4 py-3">
                        <span className="text-white font-mono text-sm">{domain.domain}</span>
                      </td>
                      <td className="px-4 py-3">
                        {domain.alias && (
                          <span className="text-blue-400 text-sm">
                            {domain.alias}.devbox.local
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-2 flex-wrap">
                          {domain.read_only && (
                            <span className="text-xs bg-yellow-900/50 text-yellow-400 px-2 py-0.5 rounded flex items-center gap-1">
                              <Shield className="w-3 h-3" />
                              Read-only
                            </span>
                          )}
                          {domain.timeout && (
                            <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {domain.timeout}
                            </span>
                          )}
                          {domain.rate_limit && (
                            <span className="text-xs bg-blue-900/50 text-blue-400 px-2 py-0.5 rounded flex items-center gap-1">
                              <Gauge className="w-3 h-3" />
                              {domain.rate_limit.requests_per_minute}/min
                            </span>
                          )}
                          {domain.credential && (
                            <span className="text-xs bg-green-900/50 text-green-400 px-2 py-0.5 rounded flex items-center gap-1">
                              <Key className="w-3 h-3" />
                              {domain.credential.env}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          <button
                            onClick={() => {
                              setEditingDomain(domain);
                              setShowDomainModal(true);
                            }}
                            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                            title="Edit"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteDomain(domain.domain)}
                            className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {(!config.domains || config.domains.length === 0) && (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                        No domains configured. Click "Add Domain" to get started.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <SettingsEditor config={config} onChange={handleSettingsChange} />
        )}

        {activeTab === 'raw' && (
          <textarea
            value={rawContent}
            onChange={handleRawChange}
            className="yaml-editor w-full h-full min-h-[500px] bg-gray-800 border border-gray-700 rounded-lg p-4 text-gray-100 font-mono text-sm focus:outline-none focus:border-blue-500 resize-none"
            spellCheck={false}
          />
        )}
      </div>

      {/* Domain Modal */}
      {showDomainModal && (
        <DomainModal
          domain={editingDomain}
          onSave={handleAddDomain}
          onClose={() => {
            setShowDomainModal(false);
            setEditingDomain(null);
          }}
          existingDomains={(config.domains || []).map((d) => d.domain)}
        />
      )}
    </div>
  );
}
