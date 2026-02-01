import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import { Button, Input } from '../components/common';
import { api } from '../api/client';

export function Login() {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Save token and test with an authenticated endpoint
      api.setToken(token);
      await api.getDataPlanes();
      // If we get here, token is valid - reload to dashboard
      window.location.href = './';
    } catch {
      setError('Invalid token or API unreachable');
      api.clearToken();
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-8">
          <div className="flex items-center justify-center mb-6">
            <div className="p-3 bg-blue-600/20 rounded-full">
              <KeyRound className="text-blue-400" size={32} />
            </div>
          </div>

          <h1 className="text-2xl font-bold text-dark-100 text-center mb-2">
            Control Plane
          </h1>
          <p className="text-dark-500 text-center mb-6">
            Enter your API token to continue
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              type="password"
              placeholder="Enter your API token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              error={error}
            />

            <Button
              type="submit"
              className="w-full"
              disabled={!token || loading}
            >
              {loading ? 'Connecting...' : 'Connect'}
            </Button>
          </form>

          <p className="text-dark-500 text-sm text-center mt-6">
            Your token is stored locally and never sent to third parties.
          </p>
        </div>
      </div>
    </div>
  );
}
