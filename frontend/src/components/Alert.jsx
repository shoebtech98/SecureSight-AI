import React from 'react';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

const Alert = ({
  type = 'info', // 'success', 'warning', 'danger', 'info'
  title,
  message,
  onClose,
  className = '',
}) => {
  const styles = {
    success: {
      bg: 'bg-success/10 border-success/30 text-success-light',
      icon: CheckCircle2,
      textColor: 'text-green-400',
      iconColor: 'text-success',
    },
    warning: {
      bg: 'bg-warning/10 border-warning/30 text-warning-light',
      icon: AlertCircle,
      textColor: 'text-amber-400',
      iconColor: 'text-warning',
    },
    danger: {
      bg: 'bg-danger/10 border-danger/30 text-danger-light',
      icon: AlertCircle,
      textColor: 'text-red-400',
      iconColor: 'text-danger',
    },
    info: {
      bg: 'bg-info/10 border-info/30 text-info-light',
      icon: Info,
      textColor: 'text-cyan-400',
      iconColor: 'text-info',
    },
  };

  const currentStyle = styles[type] || styles.info;
  const Icon = currentStyle.icon;

  return (
    <div className={`flex items-start p-4 rounded-lg border ${currentStyle.bg} ${className}`} role="alert">
      <div className="flex-shrink-0">
        <Icon className={`h-5 w-5 ${currentStyle.iconColor}`} />
      </div>
      <div className="ml-3 flex-1">
        {title && <h3 className={`text-sm font-medium ${currentStyle.textColor}`}>{title}</h3>}
        <div className={`text-xs mt-1 ${currentStyle.textColor} opacity-90`}>{message}</div>
      </div>
      {onClose && (
        <div className="ml-auto pl-3">
          <div className="-mx-1.5 -my-1.5">
            <button
              type="button"
              onClick={onClose}
              className="inline-flex rounded-md p-1.5 text-slate-500 hover:text-slate-800 focus:outline-none"
            >
              <span className="sr-only">Dismiss</span>
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Alert;
