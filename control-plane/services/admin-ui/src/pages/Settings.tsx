import { useState } from 'react';
import { Eye, EyeOff, Save, ExternalLink } from 'lucide-react';
import { Card, Button, Input } from '../components/common';
import { useHealth } from '../hooks/useApi';
import { api } from '../api/client';

export function Settings() {
  const { data: health } = useHealth();
  const [showToken, setShowToken] = useState(false);
  const [token, setToken] = useState(api.getToken() || '');
  const [saved, setSaved] = useState(false);

  const handleSaveToken = () => {
    api.setToken(token);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const maskToken = (t: string) => {
    if (t.length <= 8) return '••••••••';
    return t.slice(0, 4) + '••••••••' + t.slice(-4);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-dark-100">Settings</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* API Configuration */}
        <Card title="API Configuration">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-2">
                API Token
              </label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <Input
                    type={showToken ? 'text' : 'password'}
                    value={showToken ? token : maskToken(token)}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="Enter your API token"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300"
                  >
                    {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                <Button onClick={handleSaveToken}>
                  <Save size={16} className="mr-2" />
                  {saved ? 'Saved!' : 'Save'}
                </Button>
              </div>
              <p className="text-dark-500 text-sm mt-2">
                Token is stored locally in your browser.
              </p>
            </div>
          </div>
        </Card>

        {/* System Info */}
        <Card title="System Information">
          <div className="space-y-3">
            <div className="flex justify-between items-center py-2 border-b border-dark-700">
              <span className="text-dark-400">API Status</span>
              <span
                className={`font-medium ${
                  health?.status === 'healthy'
                    ? 'text-green-400'
                    : 'text-red-400'
                }`}
              >
                {health?.status || 'Unknown'}
              </span>
            </div>
            {health?.version && (
              <div className="flex justify-between items-center py-2 border-b border-dark-700">
                <span className="text-dark-400">API Version</span>
                <span className="text-dark-200">{health.version}</span>
              </div>
            )}
            {health?.uptime !== undefined && (
              <div className="flex justify-between items-center py-2 border-b border-dark-700">
                <span className="text-dark-400">Uptime</span>
                <span className="text-dark-200">
                  {formatUptime(health.uptime)}
                </span>
              </div>
            )}
          </div>
        </Card>

        {/* External Links */}
        <Card title="External Services">
          <div className="space-y-2">
            <a
              href="/grafana/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-between p-3 rounded-lg bg-dark-900/50 hover:bg-dark-700 transition-colors"
            >
              <div>
                <p className="text-dark-200">Grafana</p>
                <p className="text-dark-500 text-sm">Metrics and dashboards</p>
              </div>
              <ExternalLink size={16} className="text-dark-500" />
            </a>
          </div>
        </Card>

        {/* About */}
        <Card title="About">
          <div className="space-y-3 text-dark-400">
            <p>
              Control Plane Admin Console provides a web interface for managing
              your development environment containers, secrets, and security
              policies.
            </p>
            <div className="pt-2 border-t border-dark-700">
              <p className="text-dark-500 text-sm">
                Built with React, TypeScript, and Tailwind CSS
              </p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);

  return parts.length > 0 ? parts.join(' ') : '< 1m';
}
