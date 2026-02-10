import { useState } from 'react';
import {
  Building2,
  Plus,
  Trash2,
  AlertCircle,
  X,
  Users,
} from 'lucide-react';
import { Card, Badge, Button, Modal } from '@cagent/shared-ui';
import {
  useTenants,
  useCreateTenant,
  useDeleteTenant,
} from '../hooks/useApi';
import type { CreateTenantRequest } from '../types/api';

export function Tenants() {
  const { data: tenants, isLoading } = useTenants();
  const createTenant = useCreateTenant();
  const deleteTenant = useDeleteTenant();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState<CreateTenantRequest>({
    name: '',
    slug: '',
  });

  // Auto-generate slug from name
  const handleNameChange = (name: string) => {
    const slug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .substring(0, 50);
    setForm({ name, slug });
  };

  const handleCreate = async () => {
    setError(null);
    try {
      await createTenant.mutateAsync(form);
      setShowCreateModal(false);
      setForm({ name: '', slug: '' });
    } catch (e) {
      setError(`Failed to create tenant: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleDelete = async (id: number) => {
    setError(null);
    try {
      await deleteTenant.mutateAsync(id);
      setShowDeleteModal(null);
    } catch (e) {
      setError(`Failed to delete tenant: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const tenantToDelete = tenants?.find(t => t.id === showDeleteModal);

  return (
    <div className="space-y-6">
      {/* Error Toast */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-200">
          <AlertCircle size={20} className="flex-shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <X size={18} />
          </button>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Tenants</h1>
          <p className="text-dark-400 text-sm mt-1">
            Manage tenant organizations (super admin only)
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus size={16} className="mr-2" />
          Create Tenant
        </Button>
      </div>

      <Card>
        {isLoading ? (
          <div className="text-center py-8 text-dark-400">Loading tenants...</div>
        ) : !tenants || tenants.length === 0 ? (
          <div className="text-center py-8 text-dark-400">
            <Building2 size={48} className="mx-auto mb-4 opacity-50" />
            <p>No tenants found</p>
            <p className="text-sm mt-2">Create a tenant to get started</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-dark-400 border-b border-dark-700">
                  <th className="pb-3 font-medium">Name</th>
                  <th className="pb-3 font-medium">Slug</th>
                  <th className="pb-3 font-medium">Agents</th>
                  <th className="pb-3 font-medium">Created</th>
                  <th className="pb-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map((tenant) => (
                  <tr key={tenant.id} className="border-b border-dark-700/50 last:border-0">
                    <td className="py-4">
                      <div className="flex items-center gap-2">
                        <Building2 size={16} className="text-blue-400" />
                        <span className="font-medium text-dark-100">{tenant.name}</span>
                      </div>
                    </td>
                    <td className="py-4">
                      <Badge variant="default">{tenant.slug}</Badge>
                    </td>
                    <td className="py-4">
                      <div className="flex items-center gap-1 text-dark-300">
                        <Users size={14} className="text-dark-500" />
                        <span>{tenant.agent_count}</span>
                      </div>
                    </td>
                    <td className="py-4 text-dark-400 text-sm">
                      {formatDate(tenant.created_at)}
                    </td>
                    <td className="py-4 text-right">
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => setShowDeleteModal(tenant.id)}
                        disabled={tenant.agent_count > 0}
                        title={tenant.agent_count > 0 ? 'Cannot delete tenant with agents' : 'Delete tenant'}
                      >
                        <Trash2 size={14} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Create Tenant Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create Tenant"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-dark-300 mb-1">Tenant Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="e.g., Acme Corporation"
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm text-dark-300 mb-1">Slug</label>
            <input
              type="text"
              value={form.slug}
              onChange={(e) => setForm({ ...form, slug: e.target.value })}
              placeholder="e.g., acme-corp"
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-dark-500 mt-1">
              URL-safe identifier for the tenant (auto-generated from name)
            </p>
          </div>

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setShowCreateModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!form.name || !form.slug || createTenant.isPending}
            >
              {createTenant.isPending ? 'Creating...' : 'Create Tenant'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={showDeleteModal !== null}
        onClose={() => setShowDeleteModal(null)}
        title="Delete Tenant"
      >
        <div className="space-y-4">
          {tenantToDelete && tenantToDelete.agent_count > 0 ? (
            <div className="p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
              <div className="flex items-center gap-2 text-yellow-400 mb-2">
                <AlertCircle size={20} />
                <span className="font-medium">Cannot delete tenant</span>
              </div>
              <p className="text-yellow-200 text-sm">
                This tenant has {tenantToDelete.agent_count} agent(s).
                Remove all agents before deleting the tenant.
              </p>
            </div>
          ) : (
            <p className="text-dark-300">
              Are you sure you want to delete <strong>{tenantToDelete?.name}</strong>?
              This action cannot be undone.
            </p>
          )}
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setShowDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => showDeleteModal && handleDelete(showDeleteModal)}
              disabled={deleteTenant.isPending || (tenantToDelete?.agent_count ?? 0) > 0}
            >
              {deleteTenant.isPending ? 'Deleting...' : 'Delete Tenant'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
