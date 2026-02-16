import { useState, useMemo, useEffect } from 'react';
import { Plus, Edit2, Trash2, RefreshCw, RotateCcw, Globe, Search, Shield, Clock, ChevronDown } from 'lucide-react';
import { Card, Table, Button, Modal, Input, Badge } from '@cagent/shared-ui';
import {
  useDomainPolicies,
  useCreateDomainPolicy,
  useUpdateDomainPolicy,
  useDeleteDomainPolicy,
  useRotateDomainPolicyCredential,
  useSecurityProfiles,
} from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import type { DomainPolicy, CreateDomainPolicyRequest, UpdateDomainPolicyRequest } from '../types/api';

interface FormData {
  domain: string;
  alias: string;
  description: string;
  allowed_paths: string;
  requests_per_minute: string;
  burst_size: string;
  timeout: string;
  read_only: boolean;
  enable_credential: boolean;
  credential_header: string;
  credential_format: string;
  credential_value: string;
}

const emptyFormData: FormData = {
  domain: '',
  alias: '',
  description: '',
  allowed_paths: '',
  requests_per_minute: '',
  burst_size: '',
  timeout: '',
  read_only: false,
  enable_credential: false,
  credential_header: 'Authorization',
  credential_format: 'Bearer {value}',
  credential_value: '',
};

export function DomainPolicies() {
  const { selectedTenantId } = useTenant();
  const { data: profiles } = useSecurityProfiles(selectedTenantId);
  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>(undefined);

  // Auto-select the first profile (usually "default") when profiles load
  useEffect(() => {
    if (profiles?.length && selectedProfileId === undefined) {
      const defaultProfile = profiles.find(p => p.name === 'default');
      setSelectedProfileId(defaultProfile?.id ?? profiles[0].id);
    }
  }, [profiles, selectedProfileId]);

  // Reset profile selection when tenant changes
  useEffect(() => {
    setSelectedProfileId(undefined);
  }, [selectedTenantId]);

  const { data: policies = [], isLoading, refetch } = useDomainPolicies({
    profileId: selectedProfileId,
    tenantId: selectedTenantId,
  });
  const createPolicy = useCreateDomainPolicy();
  const updatePolicy = useUpdateDomainPolicy();
  const deletePolicy = useDeleteDomainPolicy();
  const rotateCredential = useRotateDomainPolicyCredential();

  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState<DomainPolicy | null>(null);
  const [deleteModal, setDeleteModal] = useState<DomainPolicy | null>(null);
  const [rotateModal, setRotateModal] = useState<DomainPolicy | null>(null);

  const [domainFilter, setDomainFilter] = useState('');

  const [formData, setFormData] = useState<FormData>(emptyFormData);
  const [rotateData, setRotateData] = useState({
    header: 'Authorization',
    format: 'Bearer {value}',
    value: '',
  });

  const filteredPolicies = useMemo(() => {
    if (!domainFilter) return policies;
    const q = domainFilter.toLowerCase();
    return policies.filter((p: DomainPolicy) =>
      p.domain.toLowerCase().includes(q) ||
      (p.alias && p.alias.toLowerCase().includes(q)) ||
      (p.description && p.description.toLowerCase().includes(q))
    );
  }, [policies, domainFilter]);

  const resetForm = () => {
    setFormData(emptyFormData);
  };

  const openEditModal = (policy: DomainPolicy) => {
    setFormData({
      domain: policy.domain,
      alias: policy.alias || '',
      description: policy.description || '',
      allowed_paths: (policy.allowed_paths || []).join('\n'),
      requests_per_minute: policy.requests_per_minute?.toString() || '',
      burst_size: policy.burst_size?.toString() || '',
      timeout: policy.timeout || '',
      read_only: policy.read_only || false,
      enable_credential: policy.has_credential || false,
      credential_header: policy.credential_header || 'Authorization',
      credential_format: policy.credential_format || 'Bearer {value}',
      credential_value: '',
    });
    setEditModal(policy);
  };

  const handleCreate = async () => {
    const paths = formData.allowed_paths
      .split('\n')
      .map((p) => p.trim())
      .filter((p) => p);

    const data: CreateDomainPolicyRequest = {
      domain: formData.domain,
      alias: formData.alias || undefined,
      description: formData.description || undefined,
      profile_id: selectedProfileId,
      allowed_paths: paths.length > 0 ? paths : undefined,
      requests_per_minute: formData.requests_per_minute ? parseInt(formData.requests_per_minute) : undefined,
      burst_size: formData.burst_size ? parseInt(formData.burst_size) : undefined,
      timeout: formData.timeout || undefined,
      read_only: formData.read_only || undefined,
    };

    if (formData.enable_credential && formData.credential_value) {
      data.credential = {
        header: formData.credential_header,
        format: formData.credential_format,
        value: formData.credential_value,
      };
    }

    try {
      await createPolicy.mutateAsync({
        data,
        tenantId: selectedTenantId ?? undefined,
      });
      setCreateModal(false);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleUpdate = async () => {
    if (!editModal) return;

    const paths = formData.allowed_paths
      .split('\n')
      .map((p) => p.trim())
      .filter((p) => p);

    const data: UpdateDomainPolicyRequest = {
      alias: formData.alias || undefined,
      description: formData.description || undefined,
      allowed_paths: paths,
      requests_per_minute: formData.requests_per_minute ? parseInt(formData.requests_per_minute) : undefined,
      burst_size: formData.burst_size ? parseInt(formData.burst_size) : undefined,
      timeout: formData.timeout || undefined,
      read_only: formData.read_only,
    };

    if (formData.enable_credential && formData.credential_value) {
      data.credential = {
        header: formData.credential_header,
        format: formData.credential_format,
        value: formData.credential_value,
      };
    }

    try {
      await updatePolicy.mutateAsync({ id: editModal.id, data });
      setEditModal(null);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleToggle = async (policy: DomainPolicy) => {
    try {
      await updatePolicy.mutateAsync({
        id: policy.id,
        data: { enabled: !policy.enabled },
      });
    } catch {
      // Error handled by mutation
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    try {
      await deletePolicy.mutateAsync(deleteModal.id);
      setDeleteModal(null);
    } catch {
      // Error handled by mutation
    }
  };

  const handleRotate = async () => {
    if (!rotateModal) return;
    try {
      await rotateCredential.mutateAsync({
        id: rotateModal.id,
        credential: {
          header: rotateData.header,
          format: rotateData.format,
          value: rotateData.value,
        },
      });
      setRotateModal(null);
      setRotateData({ header: 'Authorization', format: 'Bearer {value}', value: '' });
    } catch {
      // Error handled by mutation
    }
  };

  const openRotateModal = (policy: DomainPolicy) => {
    setRotateData({
      header: policy.credential_header || 'Authorization',
      format: policy.credential_format || 'Bearer {value}',
      value: '',
    });
    setRotateModal(policy);
  };

  const columns = [
    {
      key: 'domain',
      header: 'Domain',
      render: (policy: DomainPolicy) => (
        <div>
          <code className="text-sm text-blue-400">{policy.domain}</code>
          {policy.alias && (
            <p className="text-xs text-dark-500">{policy.alias}.devbox.local</p>
          )}
          {policy.description && (
            <p className="text-xs text-dark-500 mt-1">{policy.description}</p>
          )}
        </div>
      ),
    },
    {
      key: 'paths',
      header: 'Paths',
      render: (policy: DomainPolicy) => {
        const paths = policy.allowed_paths || [];
        if (paths.length === 0) {
          return <span className="text-dark-500 text-sm">All paths</span>;
        }
        return (
          <span className="text-sm text-dark-300">
            {paths.length} {paths.length === 1 ? 'path' : 'paths'}
          </span>
        );
      },
    },
    {
      key: 'rate_limit',
      header: 'Rate Limit',
      render: (policy: DomainPolicy) =>
        policy.requests_per_minute ? (
          <span className="text-sm text-dark-300">
            {policy.requests_per_minute}/min (burst: {policy.burst_size || '-'})
          </span>
        ) : (
          <span className="text-dark-500 text-sm">Default</span>
        ),
    },
    {
      key: 'options',
      header: 'Options',
      render: (policy: DomainPolicy) => (
        <div className="flex gap-1.5 flex-wrap">
          {policy.read_only && (
            <span className="inline-flex items-center gap-1 text-xs bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded">
              <Shield size={12} />
              Read-only
            </span>
          )}
          {policy.timeout && (
            <span className="inline-flex items-center gap-1 text-xs bg-dark-700 text-dark-300 px-2 py-0.5 rounded">
              <Clock size={12} />
              {policy.timeout}
            </span>
          )}
          {!policy.read_only && !policy.timeout && (
            <span className="text-dark-500 text-sm">—</span>
          )}
        </div>
      ),
    },
    {
      key: 'credential',
      header: 'Credential',
      render: (policy: DomainPolicy) =>
        policy.has_credential ? (
          <div>
            <Badge variant="success">Configured</Badge>
            {policy.credential_rotated_at && (
              <p className="text-xs text-dark-500 mt-1">
                Rotated: {new Date(policy.credential_rotated_at).toLocaleDateString()}
              </p>
            )}
          </div>
        ) : (
          <span className="text-dark-500 text-sm">None</span>
        ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (policy: DomainPolicy) => (
        <button onClick={() => handleToggle(policy)}>
          <Badge variant={policy.enabled ? 'success' : 'default'}>
            {policy.enabled ? 'Enabled' : 'Disabled'}
          </Badge>
        </button>
      ),
    },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      render: (policy: DomainPolicy) => (
        <div className="flex items-center justify-end gap-2">
          {policy.has_credential && (
            <Button variant="ghost" size="sm" onClick={() => openRotateModal(policy)}>
              <RotateCcw size={14} className="mr-1" />
              Rotate
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={() => openEditModal(policy)}>
            <Edit2 size={14} />
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setDeleteModal(policy)}>
            <Trash2 size={14} className="text-red-400" />
          </Button>
        </div>
      ),
    },
  ];

  const renderFormFields = (isEdit: boolean) => (
    <div className="space-y-6">
      {/* Basic Settings */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Basic Settings</h3>
        <div className="space-y-4">
          <Input
            label="Domain"
            placeholder="api.openai.com or *.github.com"
            value={formData.domain}
            onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
            disabled={isEdit}
          />
          <Input
            label="Alias (optional)"
            placeholder="openai"
            value={formData.alias}
            onChange={(e) => setFormData({ ...formData, alias: e.target.value })}
          />
          {formData.alias && (
            <p className="text-xs text-dark-500">
              Alias creates a shortcut: <code className="text-blue-400">{formData.alias}.devbox.local</code> → {formData.domain || 'domain'}
            </p>
          )}
          <Input
            label="Description (optional)"
            placeholder="OpenAI API access"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          />
        </div>
      </div>

      {/* Path Restrictions */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Path Restrictions (optional)</h3>
        <div className="space-y-2">
          <textarea
            className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm"
            rows={3}
            placeholder="/v1/chat/*&#10;/v1/models&#10;/api/v2/users/*"
            value={formData.allowed_paths}
            onChange={(e) => setFormData({ ...formData, allowed_paths: e.target.value })}
          />
          <p className="text-xs text-dark-500">
            One path pattern per line. Use * as wildcard. Leave empty to allow all paths.
          </p>
        </div>
      </div>

      {/* Rate Limiting */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Rate Limiting (optional)</h3>
        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Requests per Minute"
            type="number"
            placeholder="60"
            value={formData.requests_per_minute}
            onChange={(e) => setFormData({ ...formData, requests_per_minute: e.target.value })}
          />
          <Input
            label="Burst Size"
            type="number"
            placeholder="10"
            value={formData.burst_size}
            onChange={(e) => setFormData({ ...formData, burst_size: e.target.value })}
          />
        </div>
        <p className="text-xs text-dark-500 mt-2">
          Leave empty to use default rate limits.
        </p>
      </div>

      {/* Options */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Options</h3>
        <div className="space-y-4">
          <Input
            label="Timeout"
            placeholder="30s, 120s, 5m"
            value={formData.timeout}
            onChange={(e) => setFormData({ ...formData, timeout: e.target.value })}
          />
          <p className="text-xs text-dark-500 -mt-2">
            Request timeout for Envoy proxy. Leave empty for default.
          </p>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.read_only}
              onChange={(e) => setFormData({ ...formData, read_only: e.target.checked })}
              className="w-4 h-4 rounded border-dark-600 bg-dark-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-dark-800"
            />
            <span className="text-sm text-dark-300">Read-only (block POST/PUT/DELETE)</span>
          </label>
        </div>
      </div>

      {/* Credential */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-dark-200">Credential Injection</h3>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.enable_credential}
              onChange={(e) => setFormData({ ...formData, enable_credential: e.target.checked })}
              className="w-4 h-4 rounded border-dark-600 bg-dark-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-dark-800"
            />
            <span className="text-sm text-dark-400">Enable</span>
          </label>
        </div>
        {formData.enable_credential && (
          <div className="space-y-4 p-4 bg-dark-900/50 rounded-lg border border-dark-700">
            <div className="grid grid-cols-2 gap-4">
              <Input
                label="Header Name"
                placeholder="Authorization"
                value={formData.credential_header}
                onChange={(e) => setFormData({ ...formData, credential_header: e.target.value })}
              />
              <Input
                label="Header Format"
                placeholder="Bearer {value}"
                value={formData.credential_format}
                onChange={(e) => setFormData({ ...formData, credential_format: e.target.value })}
              />
            </div>
            <Input
              label="Credential Value"
              type="password"
              placeholder={isEdit && editModal?.has_credential ? '(unchanged)' : 'sk-...'}
              value={formData.credential_value}
              onChange={(e) => setFormData({ ...formData, credential_value: e.target.value })}
            />
            <p className="text-xs text-dark-500">
              Use {'{value}'} in header format to insert the credential.
              {isEdit && editModal?.has_credential && ' Leave value empty to keep current credential.'}
            </p>
          </div>
        )}
        {!formData.enable_credential && (
          <p className="text-xs text-dark-500">
            Enable to automatically inject credentials into requests to this domain.
          </p>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 rounded-lg">
            <Globe className="text-blue-400" size={24} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-dark-100">Egress Policies</h1>
            <p className="text-dark-400 text-sm mt-1">
              Configure access, rate limits, and credentials for external domains
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={() => refetch()}>
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </Button>
          <Button onClick={() => setCreateModal(true)} disabled={!selectedTenantId}>
            <Plus size={16} className="mr-2" />
            New Policy
          </Button>
        </div>
      </div>

      {/* Profile Selector */}
      <div>
        <label className="block text-sm font-medium text-dark-300 mb-2">
          Profile
        </label>
        <div className="relative w-72">
          <select
            value={selectedProfileId ?? ''}
            onChange={(e) => setSelectedProfileId(Number(e.target.value))}
            className="w-full appearance-none bg-dark-800 border border-dark-600 rounded-lg px-3 py-2 pr-8 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            {!profiles?.length && (
              <option value="">No profiles available</option>
            )}
            {profiles?.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <ChevronDown
            size={16}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-dark-400 pointer-events-none"
          />
        </div>
      </div>

      <Card>
        {policies.length > 0 && (
          <div className="mb-4">
            <div className="relative max-w-sm">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
              <Input
                placeholder="Filter by domain, alias, or description..."
                className="pl-9"
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
              />
            </div>
          </div>
        )}
        {isLoading || !selectedTenantId ? (
          <div className="text-center py-8 text-dark-400">
            {selectedTenantId ? 'Loading...' : 'Select a tenant to view egress policies'}
          </div>
        ) : filteredPolicies.length > 0 ? (
          <Table
            columns={columns}
            data={filteredPolicies}
            keyExtractor={(p) => p.id.toString()}
          />
        ) : policies.length > 0 ? (
          <div className="text-center py-8 text-dark-400">
            No policies match &ldquo;{domainFilter}&rdquo;
          </div>
        ) : (
          <div className="text-center py-8 text-dark-400">
            <Globe size={48} className="mx-auto mb-4 opacity-50" />
            <p>No egress policies configured</p>
            <p className="text-sm mt-2">
              Add policies to control access, rate limits, and credentials for external domains.
            </p>
          </div>
        )}
      </Card>

      {/* Create Modal */}
      <Modal
        isOpen={createModal}
        onClose={() => {
          setCreateModal(false);
          resetForm();
        }}
        title="Create Egress Policy"
        size="lg"
      >
        {renderFormFields(false)}
        <div className="flex justify-end gap-2 pt-6">
          <Button
            variant="secondary"
            onClick={() => {
              setCreateModal(false);
              resetForm();
            }}
          >
            Cancel
          </Button>
          <Button
            onClick={handleCreate}
            disabled={!formData.domain || createPolicy.isPending}
          >
            {createPolicy.isPending ? 'Creating...' : 'Create'}
          </Button>
        </div>
      </Modal>

      {/* Edit Modal */}
      <Modal
        isOpen={!!editModal}
        onClose={() => {
          setEditModal(null);
          resetForm();
        }}
        title="Edit Egress Policy"
        size="lg"
      >
        {renderFormFields(true)}
        <div className="flex justify-end gap-2 pt-6">
          <Button
            variant="secondary"
            onClick={() => {
              setEditModal(null);
              resetForm();
            }}
          >
            Cancel
          </Button>
          <Button onClick={handleUpdate} disabled={updatePolicy.isPending}>
            {updatePolicy.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </Modal>

      {/* Rotate Credential Modal */}
      <Modal
        isOpen={!!rotateModal}
        onClose={() => setRotateModal(null)}
        title="Rotate Credential"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Rotating credential for:{' '}
            <code className="text-blue-400">{rotateModal?.domain}</code>
          </p>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Header Name"
              placeholder="Authorization"
              value={rotateData.header}
              onChange={(e) => setRotateData({ ...rotateData, header: e.target.value })}
            />
            <Input
              label="Header Format"
              placeholder="Bearer {value}"
              value={rotateData.format}
              onChange={(e) => setRotateData({ ...rotateData, format: e.target.value })}
            />
          </div>
          <Input
            label="New Credential Value"
            type="password"
            placeholder="Enter new credential value"
            value={rotateData.value}
            onChange={(e) => setRotateData({ ...rotateData, value: e.target.value })}
          />
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setRotateModal(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleRotate}
              disabled={!rotateData.value || rotateCredential.isPending}
            >
              {rotateCredential.isPending ? 'Rotating...' : 'Rotate'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Egress Policy"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete the policy for{' '}
            <code className="text-blue-400">{deleteModal?.domain}</code>?
            This action cannot be undone.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={deletePolicy.isPending}
            >
              {deletePolicy.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
