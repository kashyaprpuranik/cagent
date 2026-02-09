import { ReactNode } from 'react';

interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => ReactNode;
  className?: string;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string | number;
  emptyMessage?: string;
  isLoading?: boolean;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  emptyMessage = 'No data available',
  isLoading,
}: TableProps<T>) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-dark-500">
        Loading...
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-dark-500">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-dark-700">
            {columns.map((col) => (
              <th
                key={col.key}
                className={`px-3 py-2 text-left text-xs font-medium text-dark-400 ${
                  col.className || ''
                }`}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item) => (
            <tr
              key={keyExtractor(item)}
              className="border-b border-dark-700/50 hover:bg-dark-800/50"
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={`px-3 py-1.5 text-sm text-dark-200 ${
                    col.className || ''
                  }`}
                >
                  {col.render
                    ? col.render(item)
                    : (item as Record<string, unknown>)[col.key]?.toString()}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
