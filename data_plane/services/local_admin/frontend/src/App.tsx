import { Routes, Route, NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Settings, Container, FileText, Activity, Terminal, MonitorUp } from 'lucide-react';
import { getInfo } from './api/client';
import ConfigPage from './pages/Config';
import StatusPage from './pages/Status';
import LogsPage from './pages/Logs';
import SshTunnelPage from './pages/SshTunnel';
import TerminalPage from './pages/Terminal';

function Sidebar() {
  const navItems = [
    { to: '/', icon: Activity, label: 'Status' },
    { to: '/config', icon: Settings, label: 'Config' },
    { to: '/logs', icon: FileText, label: 'Logs' },
    { to: '/terminal', icon: MonitorUp, label: 'Terminal' },
    { to: '/ssh-tunnel', icon: Terminal, label: 'SSH Tunnel' },
  ];

  return (
    <aside className="w-56 bg-gray-800 border-r border-gray-700 flex flex-col">
      <div className="p-4 border-b border-gray-700">
        <h1 className="text-lg font-bold text-white flex items-center gap-2">
          <Container className="w-5 h-5 text-blue-400" />
          Cagent
        </h1>
        <p className="text-xs text-gray-400 mt-1">Local Admin</p>
      </div>

      <nav className="flex-1 p-2">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-300 hover:bg-gray-700'
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-700 text-xs text-gray-500">
        Standalone Mode
      </div>
    </aside>
  );
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  );
}

export default function App() {
  // Prefetch system info
  useQuery({
    queryKey: ['info'],
    queryFn: getInfo,
  });

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<StatusPage />} />
        <Route path="/config" element={<ConfigPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/terminal" element={<TerminalPage />} />
        <Route path="/ssh-tunnel" element={<SshTunnelPage />} />
      </Routes>
    </Layout>
  );
}
