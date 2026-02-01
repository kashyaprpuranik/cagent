import { useState } from 'react';
import { Activity, Plus, Edit2, Trash2, Check, X } from 'lucide-react';
import { Card, Badge, Button, Modal, Select } from '../components/common';
import {
  useRateLimits,
  useCreateRateLimit,
  useUpdateRateLimit,
  useDeleteRateLimit,
  useAgents,
} from '../hooks/useApi';
import type { RateLimit, DataPlane } from '../types/api';

export function RateLimits() {
  const { data: rateLimits, isLoading } = useRateLimits();
  const { data: agents = [] } = useAgents();
  const createRateLimit = useCreateRateLimit();
  const updateRateLimit = useUpdateRateLimit();
  const deleteRateLimit = useDeleteRateLimit();

  const [createModal, setCreateModal] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [deleteModal, setDeleteModal] = useState<RateLimit | null>(null);

  const [formData, setFormData] = useState({
    domain_pattern: '',
    requests_per_minute: 60,
    burst_size: 10,
    description: '',
    agent_id: '',
  });

  // Build agent options for the Select dropdown
  const agentOptions = [
    { value: '', label: 'Global (all agents)' },
    ...agents.map((agent: DataPlane) => ({
      value: agent.agent_id,
      label: agent.agent_id,
    })),
  ];

  const resetForm = () => {
    setFormData({
      domain_pattern: '',
      requests_per_minute: 60,
      burst_size: 10,
      description: '',
      agent_id: '',
    });
  };

  const handleCreate = async () => {
    try {
      await createRateLimit.mutateAsync({
        domain_pattern: formData.domain_pattern,
        requests_per_minute: formData.requests_per_minute,
        burst_size: formData.burst_size,
        description: formData.description || undefined,
        agent_id: formData.agent_id || undefined,
      });
      setCreateModal(false);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleUpdate = async (id: number) => {
    try {
      await updateRateLimit.mutateAsync({
        id,
        data: {
          requests_per_minute: formData.requests_per_minute,
          burst_size: formData.burst_size,
          description: formData.description || undefined,
        },
      });
      setEditingId(null);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleToggle = async (rl: RateLimit) => {
    try {
      await updateRateLimit.mutateAsync({
        id: rl.id,
        data: { enabled: !rl.enabled },
      });
    } catch {
      // Error handled by mutation
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    try {
      await deleteRateLimit.mutateAsync(deleteModal.id);
      setDeleteModal(null);
    } catch {
      // Error handled by mutation
    }
  };

  const startEdit = (rl: RateLimit) => {
    setFormData({
      domain_pattern: rl.domain_pattern,
      requests_per_minute: rl.requests_per_minute,
      burst_size: rl.burst_size,
      description: rl.description || '',
      agent_id: rl.agent_id || '',
    });
    setEditingId(rl.id);
  };

  const cancelEdit = () => {
    setEditingId(null);
    resetForm();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-dark-100">Rate Limits</h1>
        <Button onClick={() => setCreateModal(true)}>
          <Plus size={16} className="mr-2" />
          Add Rate Limit
        </Button>
      </div>

      <Card>
        {isLoading ? (
          <div className="text-center py-8 text-dark-400">Loading...</div>
        ) : rateLimits && rateLimits.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-dark-400 text-sm border-b border-dark-700">
                  <th className="pb-3 font-medium">Domain Pattern</th>
                  <th className="pb-3 font-medium">Requests/Min</th>
                  <th className="pb-3 font-medium">Burst</th>
                  <th className="pb-3 font-medium">Agent</th>
                  <th className="pb-3 font-medium">Description</th>
                  <th className="pb-3 font-medium">Status</th>
                  <th className="pb-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-700">
                {rateLimits.map((rl) => (
                  <tr key={rl.id} className="text-dark-200">
                    {editingId === rl.id ? (
                      <>
                        <td className="py-3">
                          <span className="font-mono text-sm">{rl.domain_pattern}</span>
                        </td>
                        <td className="py-3">
                          <input
                            type="number"
                            value={formData.requests_per_minute}
                            onChange={(e) =>
                              setFormData({ ...formData, requests_per_minute: parseInt(e.target.value) || 60 })
                            }
                            className="w-20 px-2 py-1 bg-dark-900 border border-dark-600 rounded text-dark-100"
                          />
                        </td>
                        <td className="py-3">
                          <input
                            type="number"
                            value={formData.burst_size}
                            onChange={(e) =>
                              setFormData({ ...formData, burst_size: parseInt(e.target.value) || 10 })
                            }
                            className="w-16 px-2 py-1 bg-dark-900 border border-dark-600 rounded text-dark-100"
                          />
                        </td>
                        <td className="py-3">
                          {rl.agent_id
                            ? <Badge variant="info">{rl.agent_id}</Badge>
                            : <span className="text-sm text-dark-500">Global</span>}
                        </td>
                        <td className="py-3">
                          <input
                            type="text"
                            value={formData.description}
                            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                            className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-dark-100"
                            placeholder="Description"
                          />
                        </td>
                        <td className="py-3">
                          <Badge variant={rl.enabled ? 'success' : 'default'}>
                            {rl.enabled ? 'Enabled' : 'Disabled'}
                          </Badge>
                        </td>
                        <td className="py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleUpdate(rl.id)}
                              disabled={updateRateLimit.isPending}
                            >
                              <Check size={14} className="text-green-400" />
                            </Button>
                            <Button variant="ghost" size="sm" onClick={cancelEdit}>
                              <X size={14} className="text-red-400" />
                            </Button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="py-3">
                          <span className="font-mono text-sm">{rl.domain_pattern}</span>
                        </td>
                        <td className="py-3">{rl.requests_per_minute}</td>
                        <td className="py-3">{rl.burst_size}</td>
                        <td className="py-3">
                          {rl.agent_id
                            ? <Badge variant="info">{rl.agent_id}</Badge>
                            : <span className="text-sm text-dark-500">Global</span>}
                        </td>
                        <td className="py-3 text-dark-400 text-sm">{rl.description || '-'}</td>
                        <td className="py-3">
                          <button onClick={() => handleToggle(rl)}>
                            <Badge variant={rl.enabled ? 'success' : 'default'}>
                              {rl.enabled ? 'Enabled' : 'Disabled'}
                            </Badge>
                          </button>
                        </td>
                        <td className="py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button variant="ghost" size="sm" onClick={() => startEdit(rl)}>
                              <Edit2 size={14} />
                            </Button>
                            <Button variant="ghost" size="sm" onClick={() => setDeleteModal(rl)}>
                              <Trash2 size={14} className="text-red-400" />
                            </Button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-dark-400">
            <Activity size={48} className="mx-auto mb-4 opacity-50" />
            <p>No rate limits configured</p>
            <p className="text-sm mt-2">Add rate limits to control API request rates per domain</p>
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
        title="Add Rate Limit"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-dark-300 text-sm mb-1">Domain Pattern</label>
            <input
              type="text"
              value={formData.domain_pattern}
              onChange={(e) => setFormData({ ...formData, domain_pattern: e.target.value })}
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="api.openai.com or *.github.com"
            />
            <p className="text-dark-500 text-xs mt-1">
              Use * as wildcard prefix, e.g., *.github.com
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-dark-300 text-sm mb-1">Requests/Minute</label>
              <input
                type="number"
                value={formData.requests_per_minute}
                onChange={(e) =>
                  setFormData({ ...formData, requests_per_minute: parseInt(e.target.value) || 60 })
                }
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-dark-300 text-sm mb-1">Burst Size</label>
              <input
                type="number"
                value={formData.burst_size}
                onChange={(e) =>
                  setFormData({ ...formData, burst_size: parseInt(e.target.value) || 10 })
                }
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
              <p className="text-dark-500 text-xs mt-1">Max requests allowed in a burst</p>
            </div>
          </div>

          <div>
            <label className="block text-dark-300 text-sm mb-1">Description (optional)</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="OpenAI API rate limit"
            />
          </div>

          <Select
            label="Agent (optional)"
            options={agentOptions}
            value={formData.agent_id}
            onChange={(e) => setFormData({ ...formData, agent_id: e.target.value })}
          />
          <p className="text-xs text-dark-500">
            Select an agent to scope this rate limit to that agent only, or leave as "Global" to apply to all agents.
            Agent-specific rate limits take precedence over global rate limits.
          </p>

          <div className="flex justify-end gap-2 pt-4">
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
              disabled={!formData.domain_pattern || createRateLimit.isPending}
            >
              {createRateLimit.isPending ? 'Creating...' : 'Create'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Rate Limit"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete the rate limit for{' '}
            <span className="font-mono text-dark-100">{deleteModal?.domain_pattern}</span>?
          </p>

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={deleteRateLimit.isPending}
            >
              {deleteRateLimit.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
