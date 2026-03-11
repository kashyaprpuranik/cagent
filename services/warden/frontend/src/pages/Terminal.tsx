import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Terminal as TerminalIcon, RefreshCw, X, ChevronDown, Search, ArrowUp, ArrowDown } from 'lucide-react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { ClipboardAddon } from '@xterm/addon-clipboard';
import { WebglAddon } from '@xterm/addon-webgl';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { SearchAddon } from '@xterm/addon-search';
import { createTerminal, getContainers } from '../api/client';
import '@xterm/xterm/css/xterm.css';

const INFRA_CONTAINERS = new Set([
  'dns-filter', 'http-proxy', 'email-proxy', 'warden',
]);

export default function TerminalPage() {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const searchAddonRef = useRef<SearchAddon | null>(null);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);

  const [selectedContainer, setSelectedContainer] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Fetch containers to discover agent containers dynamically
  const { data: containersData } = useQuery({
    queryKey: ['containers'],
    queryFn: getContainers,
    refetchInterval: 10000,
  });

  // Extract agent containers (anything not infrastructure)
  const agentContainers = useMemo(
    () => containersData
      ? Object.values(containersData.containers)
          .filter((c) => !INFRA_CONTAINERS.has(c.name) && c.status === 'running')
          .map((c) => c.name)
      : [],
    [containersData],
  );

  // Auto-select first agent container
  useEffect(() => {
    if (!selectedContainer && agentContainers.length > 0) {
      setSelectedContainer(agentContainers[0]);
    }
  }, [agentContainers, selectedContainer]);

  const disconnect = useCallback(() => {
    if (resizeObserverRef.current) {
      resizeObserverRef.current.disconnect();
      resizeObserverRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }
    fitAddonRef.current = null;
    searchAddonRef.current = null;
    setIsConnected(false);
    setShowSearch(false);
    setSearchQuery('');
  }, []);

  const connect = useCallback(() => {
    if (!terminalRef.current || !selectedContainer) return;

    // Clean up previous connection
    disconnect();

    // Create terminal
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      scrollback: 10000,
      theme: {
        background: '#1a1a2e',
        foreground: '#eaeaea',
        cursor: '#eaeaea',
        cursorAccent: '#1a1a2e',
        selectionBackground: '#3d3d5c',
        black: '#1a1a2e',
        red: '#ff6b6b',
        green: '#4ecdc4',
        yellow: '#ffe66d',
        blue: '#4dabf7',
        magenta: '#da77f2',
        cyan: '#66d9ef',
        white: '#eaeaea',
        brightBlack: '#4a4a6a',
        brightRed: '#ff8787',
        brightGreen: '#69dbcf',
        brightYellow: '#fff078',
        brightBlue: '#74c0fc',
        brightMagenta: '#e599f7',
        brightCyan: '#81e6f2',
        brightWhite: '#ffffff',
      },
    });

    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(new ClipboardAddon());
    term.loadAddon(new WebLinksAddon());
    term.loadAddon(searchAddon);

    // WebGL addon with fallback on context loss
    try {
      const webglAddon = new WebglAddon();
      webglAddon.onContextLoss(() => {
        webglAddon.dispose();
      });
      term.loadAddon(webglAddon);
    } catch {
      // WebGL not available — falls back to canvas renderer
    }

    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;
    searchAddonRef.current = searchAddon;

    // Use ResizeObserver instead of window resize listener
    const resizeObserver = new ResizeObserver(() => {
      if (fitAddonRef.current) fitAddonRef.current.fit();
    });
    resizeObserver.observe(terminalRef.current);
    resizeObserverRef.current = resizeObserver;

    // Connect WebSocket to the selected container
    const ws = createTerminal(selectedContainer);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
      term.write(`\r\n\x1b[32mConnected to ${selectedContainer}\x1b[0m\r\n\r\n`);
      // Send initial size
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    };

    ws.onmessage = (event) => {
      term.write(event.data);
    };

    ws.onerror = () => {
      setError('WebSocket connection error');
      setIsConnected(false);
    };

    ws.onclose = () => {
      setIsConnected(false);
      term.write('\r\n\x1b[31mConnection closed\x1b[0m\r\n');
    };

    // Send input to WebSocket
    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    // Send resize events to backend
    term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });

    // Ctrl+Shift+F to toggle search
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === 'keydown' && e.ctrlKey && e.shiftKey && e.key === 'F') {
        setShowSearch((prev) => !prev);
        return false;
      }
      return true;
    });
  }, [selectedContainer, disconnect]);

  // Focus search input when search bar opens
  useEffect(() => {
    if (showSearch && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [showSearch]);

  const handleSearchKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setShowSearch(false);
      setSearchQuery('');
      searchAddonRef.current?.clearDecorations();
      xtermRef.current?.focus();
    } else if (e.key === 'Enter') {
      if (e.shiftKey) {
        searchAddonRef.current?.findPrevious(searchQuery);
      } else {
        searchAddonRef.current?.findNext(searchQuery);
      }
    }
  };

  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    if (value) {
      searchAddonRef.current?.findNext(value);
    } else {
      searchAddonRef.current?.clearDecorations();
    }
  };

  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <TerminalIcon className="w-6 h-6 text-green-400" />
            Web Terminal
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Interactive shell access to agent containers
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Container Selector */}
          <div className="relative">
            <select
              value={selectedContainer || ''}
              onChange={(e) => {
                const newContainer = e.target.value || null;
                if (isConnected) disconnect();
                setSelectedContainer(newContainer);
              }}
              className="appearance-none bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 pr-8 text-sm text-gray-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            >
              {agentContainers.length === 0 && (
                <option value="">No agent containers</option>
              )}
              {agentContainers.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <ChevronDown
              size={16}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none"
            />
          </div>

          {!isConnected ? (
            <button
              onClick={connect}
              disabled={!selectedContainer}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <TerminalIcon className="w-4 h-4" />
              Connect
            </button>
          ) : (
            <button
              onClick={disconnect}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
            >
              <X className="w-4 h-4" />
              Disconnect
            </button>
          )}

          {isConnected && (
            <button
              onClick={() => {
                disconnect();
                setTimeout(connect, 100);
              }}
              className="flex items-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg"
            >
              <RefreshCw className="w-4 h-4" />
              Reconnect
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-300 p-3 rounded-lg mb-4">
          {error}
        </div>
      )}

      <div className="flex items-center gap-2 mb-2">
        <span
          className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-gray-500'}`}
        />
        <span className="text-sm text-gray-400">
          {isConnected ? `Connected to ${selectedContainer}` : 'Disconnected'}
        </span>
      </div>

      {/* Search bar */}
      {showSearch && (
        <div className="flex items-center gap-2 mb-2 bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5">
          <Search size={14} className="text-gray-400 shrink-0" />
          <input
            ref={searchInputRef}
            type="text"
            value={searchQuery}
            onChange={(e) => handleSearchChange(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            placeholder="Search..."
            className="flex-1 bg-transparent text-sm text-gray-200 outline-none placeholder-gray-500"
          />
          <button
            onClick={() => searchAddonRef.current?.findPrevious(searchQuery)}
            className="p-1 text-gray-400 hover:text-gray-200"
            title="Previous (Shift+Enter)"
          >
            <ArrowUp size={14} />
          </button>
          <button
            onClick={() => searchAddonRef.current?.findNext(searchQuery)}
            className="p-1 text-gray-400 hover:text-gray-200"
            title="Next (Enter)"
          >
            <ArrowDown size={14} />
          </button>
          <button
            onClick={() => {
              setShowSearch(false);
              setSearchQuery('');
              searchAddonRef.current?.clearDecorations();
              xtermRef.current?.focus();
            }}
            className="p-1 text-gray-400 hover:text-gray-200"
            title="Close (Escape)"
          >
            <X size={14} />
          </button>
        </div>
      )}

      <div
        ref={terminalRef}
        className="flex-1 bg-[#1a1a2e] rounded-lg border border-gray-700 p-2 min-h-[400px]"
      />
    </div>
  );
}
