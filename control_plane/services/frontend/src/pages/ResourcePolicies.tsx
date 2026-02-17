import { useState, useEffect } from 'react';
import { ChevronDown, AlertTriangle, CheckCircle } from 'lucide-react';
import { Card } from '@cagent/ui';
import { useAuth } from '../contexts/AuthContext';
import { useTenant } from '../contexts/TenantContext';
import { useSecurityProfiles, useUpdateSecurityProfile } from '../hooks/useApi';

export function ResourcePolicies() {
  const { user } = useAuth();
  const { selectedTenantId } = useTenant();
  const { data: profiles, isLoading } = useSecurityProfiles(selectedTenantId);
  const updateProfile = useUpdateSecurityProfile();

  const hasAdminRole = user?.roles?.includes('admin') || user?.is_super_admin;

  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>(undefined);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [cpuLimit, setCpuLimit] = useState('');
  const [memoryLimitMb, setMemoryLimitMb] = useState('');
  const [pidsLimit, setPidsLimit] = useState('');

  // Auto-select the default profile
  useEffect(() => {
    if (profiles?.length && selectedProfileId === undefined) {
      const defaultProfile = profiles.find(p => p.name === 'default');
      setSelectedProfileId(defaultProfile?.id ?? profiles[0].id);
    }
  }, [profiles, selectedProfileId]);

  // Reset when tenant changes
  useEffect(() => {
    setSelectedProfileId(undefined);
  }, [selectedTenantId]);

  const effectiveProfileId = selectedProfileId ?? profiles?.find(p => p.name === 'default')?.id ?? profiles?.[0]?.id;
  const selectedProfile = profiles?.find(p => p.id === effectiveProfileId);

  // Sync form state with selected profile
  useEffect(() => {
    if (selectedProfile) {
      setCpuLimit(selectedProfile.cpu_limit != null ? String(selectedProfile.cpu_limit) : '');
      setMemoryLimitMb(selectedProfile.memory_limit_mb != null ? String(selectedProfile.memory_limit_mb) : '');
      setPidsLimit(selectedProfile.pids_limit != null ? String(selectedProfile.pids_limit) : '');
    }
  }, [selectedProfile]);

  const handleSave = () => {
    if (!effectiveProfileId || !hasAdminRole) return;
    setError(null);
    setSuccess(null);

    const data: Record<string, number | undefined> = {};
    // Send 0 to clear (backend treats 0 as null)
    data.cpu_limit = cpuLimit ? parseFloat(cpuLimit) : 0;
    data.memory_limit_mb = memoryLimitMb ? parseInt(memoryLimitMb, 10) : 0;
    data.pids_limit = pidsLimit ? parseInt(pidsLimit, 10) : 0;

    updateProfile.mutate(
      { id: effectiveProfileId, data },
      {
        onSuccess: () => {
          setSuccess('Resource limits updated. Changes take effect on next heartbeat cycle (~30s).');
          setTimeout(() => setSuccess(null), 5000);
        },
        onError: (err) => {
          setError((err as Error).message || 'Failed to update resource limits');
        },
      }
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Resource Policies</h1>
        <p className="text-sm text-dark-400 mt-1">
          Configure CPU, memory, and process limits for agent containers
        </p>
      </div>

      {/* Profile Selector */}
      <div>
        <label className="block text-sm font-medium text-dark-300 mb-2">
          Profile
        </label>
        <div className="relative w-72">
          <select
            value={effectiveProfileId ?? ''}
            onChange={(e) => {
              setSelectedProfileId(Number(e.target.value));
              setSuccess(null);
              setError(null);
            }}
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

      {/* Messages */}
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

      {/* Resource Limits */}
      {isLoading ? (
        <p className="text-dark-400">Loading profiles...</p>
      ) : effectiveProfileId ? (
        <Card title="Container Resource Limits">
          <div className="space-y-6">
            <p className="text-sm text-dark-400">
              Set resource limits for agents assigned to &ldquo;{selectedProfile?.name}&rdquo;.
              Leave blank for no limit (container/compose defaults).
              Changes take effect on the next heartbeat cycle.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">
                  CPU Limit (cores)
                </label>
                <input
                  type="number"
                  step="0.5"
                  min="0"
                  value={cpuLimit}
                  onChange={(e) => setCpuLimit(e.target.value)}
                  disabled={!hasAdminRole || updateProfile.isPending}
                  placeholder="e.g., 2.0"
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-60"
                />
                <p className="text-xs text-dark-500 mt-1">Number of CPU cores (e.g., 0.5, 1.0, 2.0)</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">
                  Memory Limit (MB)
                </label>
                <input
                  type="number"
                  step="256"
                  min="0"
                  value={memoryLimitMb}
                  onChange={(e) => setMemoryLimitMb(e.target.value)}
                  disabled={!hasAdminRole || updateProfile.isPending}
                  placeholder="e.g., 2048"
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-60"
                />
                <p className="text-xs text-dark-500 mt-1">Memory in megabytes (e.g., 512, 2048, 4096)</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">
                  PIDs Limit
                </label>
                <input
                  type="number"
                  step="1"
                  min="0"
                  value={pidsLimit}
                  onChange={(e) => setPidsLimit(e.target.value)}
                  disabled={!hasAdminRole || updateProfile.isPending}
                  placeholder="e.g., 256"
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-60"
                />
                <p className="text-xs text-dark-500 mt-1">Max number of processes (e.g., 128, 256, 512)</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <button
                onClick={handleSave}
                disabled={!hasAdminRole || updateProfile.isPending}
                className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {updateProfile.isPending ? 'Saving...' : 'Save Changes'}
              </button>
              {!hasAdminRole && (
                <p className="text-sm text-dark-500">
                  Admin role required to change resource policies.
                </p>
              )}
            </div>
          </div>
        </Card>
      ) : (
        <p className="text-dark-400">No profiles available. Create a profile first.</p>
      )}
    </div>
  );
}
