import { useState, useEffect } from 'react';
import { ChevronDown, AlertTriangle, CheckCircle } from 'lucide-react';
import { Card } from '@cagent/shared-ui';
import { useAuth } from '../contexts/AuthContext';
import { useTenant } from '../contexts/TenantContext';
import { useSecurityProfiles, useUpdateSecurityProfile } from '../hooks/useApi';
import type { SeccompProfile } from '../types/api';

const PROFILE_INFO: Record<SeccompProfile, { label: string; description: string; variant: 'default' | 'warning' | 'success' }> = {
  standard: {
    label: 'Standard',
    description: 'Blocks all syscalls by default, explicitly allows ~150 needed for normal operation. Includes mount, ptrace, and unshare. Recommended for development.',
    variant: 'default',
  },
  hardened: {
    label: 'Hardened',
    description: 'Standard profile minus dangerous syscalls: mount, umount2, ptrace, personality, setns, unshare, pivot_root, chroot, sethostname, setdomainname, reboot, init_module, delete_module, finit_module. Recommended for production.',
    variant: 'success',
  },
  permissive: {
    label: 'Permissive',
    description: 'Allows all syscalls except raw socket creation. Use only for debugging when the standard profile blocks required operations.',
    variant: 'warning',
  },
};

export function RuntimePolicies() {
  const { user } = useAuth();
  const { selectedTenantId } = useTenant();
  const { data: profiles, isLoading } = useSecurityProfiles(selectedTenantId);
  const updateProfile = useUpdateSecurityProfile();

  const hasAdminRole = user?.roles?.includes('admin') || user?.is_super_admin;

  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>(undefined);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

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

  // Compute effective profile: use selectedProfileId, or derive from profiles directly
  const effectiveProfileId = selectedProfileId ?? profiles?.find(p => p.name === 'default')?.id ?? profiles?.[0]?.id;
  const selectedProfile = profiles?.find(p => p.id === effectiveProfileId);
  const currentSeccomp = (selectedProfile?.seccomp_profile || 'standard') as SeccompProfile;

  const handleProfileChange = (seccomp: SeccompProfile) => {
    if (!effectiveProfileId || !hasAdminRole) return;
    setError(null);
    setSuccess(null);

    updateProfile.mutate(
      { id: effectiveProfileId, data: { seccomp_profile: seccomp } },
      {
        onSuccess: () => {
          setSuccess('Seccomp profile updated. Change will take effect on next heartbeat cycle (~30s).');
          setTimeout(() => setSuccess(null), 5000);
        },
        onError: (err) => {
          setError((err as Error).message || 'Failed to update runtime policy');
        },
      }
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Runtime Policies</h1>
        <p className="text-sm text-dark-400 mt-1">
          Configure seccomp profiles to control syscall access for agent containers
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

      {/* Profile Selection */}
      {isLoading ? (
        <p className="text-dark-400">Loading profiles...</p>
      ) : effectiveProfileId ? (
        <Card title="Seccomp Profile">
          <div className="space-y-4">
            <p className="text-sm text-dark-400">
              Select the syscall filtering profile for agents assigned to &ldquo;{selectedProfile?.name}&rdquo;.
              Changes require a container recreation and take effect on the next heartbeat cycle.
            </p>

            <div className="space-y-3">
              {(Object.entries(PROFILE_INFO) as [SeccompProfile, typeof PROFILE_INFO['standard']][]).map(
                ([key, info]) => (
                  <label
                    key={key}
                    className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                      currentSeccomp === key
                        ? 'border-blue-500 bg-blue-900/20'
                        : 'border-dark-600 hover:border-dark-500 bg-dark-800'
                    } ${!hasAdminRole ? 'opacity-60 cursor-not-allowed' : ''}`}
                  >
                    <input
                      type="radio"
                      name="seccomp_profile"
                      value={key}
                      checked={currentSeccomp === key}
                      onChange={() => handleProfileChange(key)}
                      disabled={!hasAdminRole || updateProfile.isPending}
                      className="mt-1 w-4 h-4 text-blue-600 bg-dark-800 border-dark-600"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-dark-100">{info.label}</span>
                        {info.variant === 'success' && (
                          <span className="text-[10px] font-medium bg-green-600/20 text-green-400 px-1.5 py-0.5 rounded">
                            Production
                          </span>
                        )}
                        {info.variant === 'warning' && (
                          <span className="text-[10px] font-medium bg-yellow-600/20 text-yellow-400 px-1.5 py-0.5 rounded">
                            Debug only
                          </span>
                        )}
                        {key === 'standard' && (
                          <span className="text-[10px] font-medium bg-blue-600/20 text-blue-400 px-1.5 py-0.5 rounded">
                            Default
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-dark-400 mt-1">{info.description}</p>
                    </div>
                  </label>
                )
              )}
            </div>

            {currentSeccomp === 'permissive' && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-900/30 border border-yellow-700 text-yellow-300 text-sm">
                <AlertTriangle size={16} className="flex-shrink-0" />
                <span>
                  Permissive mode significantly reduces container security.
                  Use only for temporary debugging and switch back when done.
                </span>
              </div>
            )}

            {!hasAdminRole && (
              <p className="text-sm text-dark-500">
                Admin role required to change runtime policies.
              </p>
            )}
          </div>
        </Card>
      ) : (
        <p className="text-dark-400">No profiles available. Create a profile first.</p>
      )}
    </div>
  );
}
