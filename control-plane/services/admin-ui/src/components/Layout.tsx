import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { useHealth } from '../hooks/useApi';

export function Layout() {
  const { data: health } = useHealth();

  return (
    <div className="flex h-screen bg-dark-950">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 bg-dark-900 border-b border-dark-700 flex items-center justify-between px-6">
          <div />
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'
                }`}
              />
              <span className="text-sm text-dark-400">
                API: {health?.status || 'checking...'}
              </span>
            </div>
          </div>
        </header>
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
