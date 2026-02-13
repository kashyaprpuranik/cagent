import { ReactNode } from 'react';

interface CardProps {
  title?: string;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
}

export function Card({ title, children, className = '', action }: CardProps) {
  return (
    <div className={`bg-surface-800 rounded-lg border border-surface-700 ${className}`}>
      {title && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-700">
          <h3 className="font-medium text-surface-100">{title}</h3>
          {action}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
