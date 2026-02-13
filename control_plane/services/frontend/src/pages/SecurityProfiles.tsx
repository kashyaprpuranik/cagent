import { useState } from 'react';
import { Plus, Pencil, Trash2, ShieldCheck, AlertTriangle, CheckCircle, X, Users } from 'lucide-react';
import { Card } from '@cagent/shared-ui';
import { useTenant } from '../contexts/TenantContext';
import {
  useSecurityProfiles,
  useCreateSecurityProfile,
  useUpdateSecurityProfile,
  useDeleteSecurityProfile,
  useDataPlanes,
  useAssignAgentProfile,
  useUnassignAgentProfile,
  useAgentStatus,
} from '../hooks/useApi';
import type { SecurityProfile, CreateSecurityProfileRequest, UpdateSecurityProfileRequest } from '../types/api';

interface ProfileModalProps {
  profile?: SecurityProfile;
  onClose: () => void;
  onSave: (data: CreateSecurityProfileRequest | UpdateSecurityProfileRequest) => void;
  isPending: boolean;
}

function ProfileModal({ profile, onClose, onSave, isPending }: ProfileModalProps) {
  const [name, setName] = useState(profile?.name || '');
  const [description, setDescription] = useState(profile?.description || '');

  const isDefault = profile?.name === 'default';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const data: CreateSecurityProfileRequest = {
      name: name.trim(),
      description: description.trim() || undefined,
    };
    onSave(data);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-dark-800 rounded-xl border border-dark-600 p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-dark-100">
            {profile ? 'Edit Profile' : 'Create Profile'}
          </h2>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-200">
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="e.g., production-strict"
              required
              disabled={isDefault}
            />
            {isDefault && (
              <p className="text-xs text-dark-500 mt-1">The default profile name cannot be changed.</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-dark-300 mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="Optional description"
            />
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-dark-300 hover:text-dark-100 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isPending || !name.trim()}
              className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {isPending ? 'Saving...' : profile ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function SecurityProfiles() {
  const { selectedTenantId } = useTenant();
  const { data: profiles, isLoading } = useSecurityProfiles(selectedTenantId);
  const { data: agents } = useDataPlanes(selectedTenantId);
  const createProfile = useCreateSecurityProfile();
  const updateProfile = useUpdateSecurityProfile();
  const deleteProfile = useDeleteSecurityProfile();
  const assignProfile = useAssignAgentProfile();
  const unassignProfile = useUnassignAgentProfile();

  const [showModal, setShowModal] = useState(false);
  const [editingProfile, setEditingProfile] = useState<SecurityProfile | undefined>();
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Agent assignment state
  const [assignAgentId, setAssignAgentId] = useState('');
  const [assignProfileId, setAssignProfileId] = useState('');

  // For showing current profile of selected agent
  const { data: agentStatus } = useAgentStatus(assignAgentId || null);

  const handleCreate = (data: CreateSecurityProfileRequest | UpdateSecurityProfileRequest) => {
    setError(null);
    createProfile.mutate(
      { data: data as CreateSecurityProfileRequest },
      {
        onSuccess: () => {
          setShowModal(false);
          setSuccess('Profile created successfully');
          setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err) => setError((err as Error).message),
      }
    );
  };

  const handleUpdate = (data: CreateSecurityProfileRequest | UpdateSecurityProfileRequest) => {
    if (!editingProfile) return;
    setError(null);
    updateProfile.mutate(
      { id: editingProfile.id, data: data as UpdateSecurityProfileRequest },
      {
        onSuccess: () => {
          setEditingProfile(undefined);
          setSuccess('Profile updated successfully');
          setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err) => setError((err as Error).message),
      }
    );
  };

  const handleDelete = (profile: SecurityProfile) => {
    if (!confirm(`Delete profile "${profile.name}"?`)) return;
    setError(null);
    deleteProfile.mutate(profile.id, {
      onSuccess: () => {
        setSuccess('Profile deleted');
        setTimeout(() => setSuccess(null), 3000);
      },
      onError: (err) => setError((err as Error).message),
    });
  };

  const handleAssign = () => {
    if (!assignAgentId || !assignProfileId) return;
    setError(null);
    assignProfile.mutate(
      { agentId: assignAgentId, data: { profile_id: Number(assignProfileId) } },
      {
        onSuccess: () => {
          setSuccess('Profile assigned to agent');
          setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err) => setError((err as Error).message),
      }
    );
  };

  const handleUnassign = () => {
    if (!assignAgentId) return;
    setError(null);
    unassignProfile.mutate(assignAgentId, {
      onSuccess: () => {
        setSuccess('Profile unassigned from agent');
        setTimeout(() => setSuccess(null), 3000);
      },
      onError: (err) => setError((err as Error).message),
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Profiles</h1>
          <p className="text-sm text-dark-400 mt-1">
            Named policy bundles combining egress rules, runtime settings, and resource limits
          </p>
        </div>
        <button
          onClick={() => { setShowModal(true); setError(null); }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus size={16} />
          New Profile
        </button>
      </div>

      {success && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-green-900/30 border border-green-700 text-green-300 text-sm">
          <CheckCircle size={16} />
          {success}
        </div>
      )}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Profiles Table */}
      <Card title="Profiles">
        {isLoading ? (
          <p className="text-dark-400">Loading...</p>
        ) : !profiles?.length ? (
          <p className="text-dark-400">No profiles created yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-dark-400 border-b border-dark-700">
                  <th className="pb-2 font-medium">Name</th>
                  <th className="pb-2 font-medium">Seccomp</th>
                  <th className="pb-2 font-medium">Resources</th>
                  <th className="pb-2 font-medium">Agents</th>
                  <th className="pb-2 font-medium">Policies</th>
                  <th className="pb-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-700">
                {profiles.map((profile) => (
                  <tr key={profile.id} className="text-dark-200">
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <ShieldCheck size={16} className="text-blue-400" />
                        <span className="font-medium">{profile.name}</span>
                      </div>
                      {profile.description && (
                        <p className="text-xs text-dark-400 mt-0.5 ml-6">{profile.description}</p>
                      )}
                    </td>
                    <td className="py-3">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        profile.seccomp_profile === 'hardened'
                          ? 'bg-green-600/20 text-green-400'
                          : profile.seccomp_profile === 'permissive'
                            ? 'bg-yellow-600/20 text-yellow-400'
                            : 'bg-dark-600 text-dark-300'
                      }`}>
                        {profile.seccomp_profile}
                      </span>
                    </td>
                    <td className="py-3">
                      {profile.cpu_limit || profile.memory_limit_mb || profile.pids_limit ? (
                        <div className="text-xs text-dark-300 space-y-0.5">
                          {profile.cpu_limit && <div>CPU: {profile.cpu_limit} cores</div>}
                          {profile.memory_limit_mb && <div>Mem: {profile.memory_limit_mb} MB</div>}
                          {profile.pids_limit && <div>PIDs: {profile.pids_limit}</div>}
                        </div>
                      ) : (
                        <span className="text-xs text-dark-500">Default</span>
                      )}
                    </td>
                    <td className="py-3 text-dark-300">{profile.agent_count}</td>
                    <td className="py-3 text-dark-300">{profile.policy_count}</td>
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => { setEditingProfile(profile); setError(null); }}
                          className="text-dark-400 hover:text-blue-400 transition-colors"
                          title="Edit"
                        >
                          <Pencil size={16} />
                        </button>
                        {profile.name !== 'default' && (
                          <button
                            onClick={() => handleDelete(profile)}
                            className="text-dark-400 hover:text-red-400 transition-colors"
                            title="Delete"
                          >
                            <Trash2 size={16} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Agent Assignment */}
      <Card title="Agent Assignment">
        <div className="space-y-4">
          <p className="text-sm text-dark-400">
            Assign a profile to an agent. The agent will use the profile&apos;s egress policies, runtime settings, and resource limits.
          </p>

          <div className="flex items-end gap-4 flex-wrap">
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1">Agent</label>
              <select
                value={assignAgentId}
                onChange={(e) => setAssignAgentId(e.target.value)}
                className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 min-w-[200px]"
              >
                <option value="">Select agent...</option>
                {agents?.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>{a.agent_id}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1">Profile</label>
              <select
                value={assignProfileId}
                onChange={(e) => setAssignProfileId(e.target.value)}
                className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 min-w-[200px]"
              >
                <option value="">Select profile...</option>
                {profiles?.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <button
              onClick={handleAssign}
              disabled={!assignAgentId || !assignProfileId || assignProfile.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              <Users size={16} />
              Assign
            </button>

            <button
              onClick={handleUnassign}
              disabled={!assignAgentId || unassignProfile.isPending}
              className="px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-500 disabled:opacity-50 transition-colors"
            >
              Unassign
            </button>
          </div>

          {assignAgentId && agentStatus && (
            <div className="text-sm text-dark-400">
              Current profile: {agentStatus.security_profile_name ? (
                <span className="text-dark-200 font-medium">{agentStatus.security_profile_name}</span>
              ) : (
                <span className="text-dark-500">None (uses default)</span>
              )}
            </div>
          )}
        </div>
      </Card>

      {/* Create Modal */}
      {showModal && (
        <ProfileModal
          onClose={() => setShowModal(false)}
          onSave={handleCreate}
          isPending={createProfile.isPending}
        />
      )}

      {/* Edit Modal */}
      {editingProfile && (
        <ProfileModal
          profile={editingProfile}
          onClose={() => setEditingProfile(undefined)}
          onSave={handleUpdate}
          isPending={updateProfile.isPending}
        />
      )}
    </div>
  );
}
