import { useState } from 'react';
import { Plus, Trash2, Download, ToggleLeft, ToggleRight } from 'lucide-react';
import { Card, Table, Button, Modal, Input, Select, Badge } from '../components/common';
import {
  useAllowlist,
  useAddAllowlistEntry,
  useUpdateAllowlistEntry,
  useDeleteAllowlistEntry,
  useAgents,
} from '../hooks/useApi';
import type { AllowlistEntry, CreateAllowlistEntryRequest, DataPlane } from '../types/api';

export function Allowlist() {
  const { data: entries = [], isLoading } = useAllowlist('domain');
  const { data: agents = [] } = useAgents();
  const addEntry = useAddAllowlistEntry();
  const updateEntry = useUpdateAllowlistEntry();
  const deleteEntry = useDeleteAllowlistEntry();

  const [addModal, setAddModal] = useState(false);
  const [deleteModal, setDeleteModal] = useState<AllowlistEntry | null>(null);

  const [newValue, setNewValue] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newAgentId, setNewAgentId] = useState('');

  // Build agent options for the Select dropdown
  const agentOptions = [
    { value: '', label: 'Global (all agents)' },
    ...agents.map((agent: DataPlane) => ({
      value: agent.agent_id,
      label: agent.agent_id,
    })),
  ];

  const handleAdd = async () => {
    try {
      const data: CreateAllowlistEntryRequest = {
        entry_type: 'domain',
        value: newValue,
        description: newDescription || undefined,
        enabled: true,
        agent_id: newAgentId || undefined,
      };
      await addEntry.mutateAsync(data);
      setAddModal(false);
      setNewValue('');
      setNewDescription('');
      setNewAgentId('');
    } catch {
      // Error handled by mutation
    }
  };

  const handleToggle = async (entry: AllowlistEntry) => {
    try {
      await updateEntry.mutateAsync({
        id: entry.id,
        data: { enabled: !entry.enabled },
      });
    } catch {
      // Error handled by mutation
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    try {
      await deleteEntry.mutateAsync(deleteModal.id);
      setDeleteModal(null);
    } catch {
      // Error handled by mutation
    }
  };

  const handleExport = () => {
    const data = entries.map((e) => ({
      value: e.value,
      enabled: e.enabled,
      description: e.description,
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'allowlist-domains.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const columns = [
    {
      key: 'value',
      header: 'Domain',
      render: (entry: AllowlistEntry) => (
        <code className="bg-dark-900 px-2 py-1 rounded text-sm">
          {entry.value}
        </code>
      ),
    },
    {
      key: 'description',
      header: 'Description',
      render: (entry: AllowlistEntry) => (
        <span className="text-dark-400">{entry.description || '-'}</span>
      ),
    },
    {
      key: 'agent_id',
      header: 'Agent',
      render: (entry: AllowlistEntry) => (
        entry.agent_id
          ? <Badge variant="info">{entry.agent_id}</Badge>
          : <span className="text-sm text-dark-500">Global</span>
      ),
    },
    {
      key: 'enabled',
      header: 'Status',
      render: (entry: AllowlistEntry) =>
        entry.enabled ? (
          <Badge variant="success">Enabled</Badge>
        ) : (
          <Badge variant="default">Disabled</Badge>
        ),
    },
    {
      key: 'created_at',
      header: 'Created',
      render: (entry: AllowlistEntry) =>
        new Date(entry.created_at).toLocaleDateString(),
    },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      render: (entry: AllowlistEntry) => (
        <div className="flex items-center justify-end gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleToggle(entry)}
            title={entry.enabled ? 'Disable' : 'Enable'}
          >
            {entry.enabled ? (
              <ToggleRight size={18} className="text-green-500" />
            ) : (
              <ToggleLeft size={18} className="text-dark-500" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDeleteModal(entry)}
          >
            <Trash2 size={14} />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Domain Allowlist</h1>
          <p className="text-dark-400 text-sm mt-1">
            Domains allowed for agent network access. Synced to CoreDNS every 5 minutes.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={handleExport}>
            <Download size={16} className="mr-2" />
            Export
          </Button>
          <Button onClick={() => setAddModal(true)}>
            <Plus size={16} className="mr-2" />
            Add Domain
          </Button>
        </div>
      </div>

      <Card>
        <Table
          columns={columns}
          data={entries}
          keyExtractor={(e) => e.id}
          isLoading={isLoading}
          emptyMessage="No domains in allowlist"
        />
      </Card>

      {/* Add Modal */}
      <Modal
        isOpen={addModal}
        onClose={() => setAddModal(false)}
        title="Add Domain"
      >
        <div className="space-y-4">
          <Input
            label="Domain"
            placeholder="example.com or *.example.com"
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
          />
          <Input
            label="Description (optional)"
            placeholder="Why is this allowed?"
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
          />
          <Select
            label="Agent (optional)"
            options={agentOptions}
            value={newAgentId}
            onChange={(e) => setNewAgentId(e.target.value)}
          />
          <p className="text-xs text-dark-500">
            Select an agent to scope this entry to that agent only, or leave as "Global" to apply to all agents.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setAddModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleAdd}
              disabled={!newValue || addEntry.isPending}
            >
              {addEntry.isPending ? 'Adding...' : 'Add Entry'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Entry"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete this entry?
          </p>
          <code className="block bg-dark-900 px-3 py-2 rounded text-sm">
            {deleteModal?.value}
          </code>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={deleteEntry.isPending}
            >
              {deleteEntry.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
