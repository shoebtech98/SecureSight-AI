const Input = ({
  label,
  id,
  type = 'text',
  placeholder = '',
  value,
  onChange,
  required = false,
  error = '',
  helperText = '',
  icon: Icon,
  rightIcon: RightIcon,
  onRightIconClick,
  rightActionLabel,
  rightActionPressed,
  tone = 'light',
  disabled = false,
  className = '',
  'aria-describedby': extraDescription,
  ...props
}) => {
  const dark = tone === 'dark';
  const describedBy = [extraDescription, helperText && `${id}-help`, error && `${id}-error`].filter(Boolean).join(' ') || undefined;

  return (
    <div className={dark ? `auth-field ${className}` : `mb-4 w-full ${className}`}>
      {label && (
        <label htmlFor={id} className={dark ? 'auth-field-label' : 'block text-sm font-medium text-slate-700 mb-1.5'}>
          {label} {required && <span aria-hidden="true" className={dark ? 'auth-required' : 'text-danger'}>*</span>}
        </label>
      )}
      <div className={dark ? `auth-input-wrap ${error ? 'has-error' : ''}` : 'relative rounded-lg shadow-sm'}>
        {Icon && <span aria-hidden="true" className={dark ? 'auth-input-icon' : 'absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500'}><Icon size={18} /></span>}
        <input
          type={type} id={id} value={value} onChange={onChange} placeholder={placeholder}
          required={required} disabled={disabled} aria-invalid={!!error} aria-describedby={describedBy}
          className={dark ? `auth-input ${Icon ? 'has-icon' : ''} ${RightIcon ? 'has-action' : ''}` : `block w-full rounded-lg bg-white border ${error ? 'border-danger focus:ring-danger/20 focus:border-danger' : 'border-slate-300 focus:ring-primary/20 focus:border-primary'} ${Icon ? 'pl-10' : 'pl-3.5'} ${RightIcon ? 'pr-12' : 'pr-3.5'} py-2.5 text-slate-800 placeholder-slate-500 focus:outline-none focus:ring-2 transition-all duration-200 text-sm disabled:opacity-50`}
          {...props}
        />
        {RightIcon && (
          <button type="button" onClick={onRightIconClick} disabled={disabled}
            aria-label={rightActionLabel || 'Toggle field visibility'} title={rightActionLabel || 'Toggle field visibility'}
            aria-pressed={rightActionPressed}
            className={dark ? 'auth-input-action' : 'absolute inset-y-0 right-0 w-11 flex items-center justify-center text-slate-500 hover:text-slate-800 focus-visible:outline-2 focus-visible:outline-primary rounded-r-lg disabled:opacity-50'}>
            <RightIcon size={18} aria-hidden="true" />
          </button>
        )}
      </div>
      {helperText && <p id={`${id}-help`} className={dark ? 'auth-field-help' : 'mt-1.5 text-xs text-slate-500'}>{helperText}</p>}
      {error && <p id={`${id}-error`} className={dark ? 'auth-field-error' : 'mt-1.5 text-xs text-danger font-medium'} role="alert">{error}</p>}
    </div>
  );
};

export default Input;
