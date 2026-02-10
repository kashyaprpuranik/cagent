import { useEffect, useRef, useState } from 'react';
import { Terminal as TerminalIcon, RefreshCw, X } from 'lucide-react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { createTerminal } from '../api/client';
import '@xterm/xterm/css/xterm.css';

export default function TerminalPage() {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = () => {
    if (!terminalRef.current) return;

    // Clean up previous connection
    disconnect();

    // Create terminal
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
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
    term.loadAddon(fitAddon);

    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    // Connect WebSocket - always connect to the agent container
    const ws = createTerminal('agent');
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
      term.write('\r\n\x1b[32mConnected to agent\x1b[0m\r\n\r\n');
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

    // Handle resize
    const handleResize = () => {
      if (fitAddonRef.current) {
        fitAddonRef.current.fit();
      }
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  };

  const disconnect = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }
    setIsConnected(false);
  };

  useEffect(() => {
    return () => {
      disconnect();
    };
  }, []);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <TerminalIcon className="w-6 h-6 text-green-400" />
            Web Terminal
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Interactive shell access to the agent container
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!isConnected ? (
            <button
              onClick={connect}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg"
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
          {isConnected ? 'Connected to agent' : 'Disconnected'}
        </span>
      </div>

      <div
        ref={terminalRef}
        className="flex-1 bg-[#1a1a2e] rounded-lg border border-gray-700 p-2 min-h-[400px]"
      />
    </div>
  );
}
