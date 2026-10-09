import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Check, Eye, EyeOff, LockKeyhole, Mail, UserRound } from 'lucide-react';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import AuthShell from '../components/AuthShell';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRules = [
  { label: '8 or more characters', test: (value) => value.length >= 8 },
  { label: 'Uppercase and lowercase letters', test: (value) => /[A-Z]/.test(value) && /[a-z]/.test(value) },
  { label: 'A number and a special character', test: (value) => /\d/.test(value) && /[^A-Za-z0-9]/.test(value) },
  { label: '72 bytes or fewer', test: (value) => new TextEncoder().encode(value).length <= 72 },
];

const Register = () => {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [registered, setRegistered] = useState(false);

  const updateField = (field, value, setter) => {
    setter(value);
    setErrors((current) => ({ ...current, [field]: undefined, form: undefined }));
  };

  const handleRegister = async (event) => {
    event.preventDefault();
    if (isLoading) return;
    const nextErrors = {};
    if (!fullName.trim()) nextErrors.fullName = 'Enter your full name.';
    if (!email.trim()) nextErrors.email = 'Enter your email address.';
    else if (!EMAIL_PATTERN.test(email.trim())) nextErrors.email = 'Enter a valid email address.';
    if (!password) nextErrors.password = 'Create a password.';
    else if (passwordRules.some((rule) => !rule.test(password))) nextErrors.password = 'Meet all password requirements below.';
    if (!confirmPassword) nextErrors.confirmPassword = 'Confirm your password.';
    else if (password !== confirmPassword) nextErrors.confirmPassword = 'Passwords do not match.';
    if (Object.keys(nextErrors).length) {
      setErrors(nextErrors);
      const first = ['fullName', 'email', 'password', 'confirmPassword'].find((key) => nextErrors[key]);
      document.getElementById(`register-${first}`)?.focus();
      return;
    }

    setErrors({});
    setIsLoading(true);
    try {
      const response = await api.post('/api/auth/register', {
        full_name: fullName.trim(), email: email.trim(), password,
      });
      setRecoveryCode(response.data.recovery_code);
      setRegistered(true);
    } catch (error) {
      const detail = error.response?.data?.detail;
      if (error.response?.status === 400 && detail === 'Email already registered') {
        setErrors({ email: 'An account with this email already exists.' });
        document.getElementById('register-email')?.focus();
      } else if (error.response?.status === 429) {
        setErrors({ form: 'Too many registration attempts. Please try again shortly.' });
      } else if (error.response?.status === 422) {
        const field = Array.isArray(detail) ? detail[0]?.loc?.at(-1) : null;
        if (field === 'email') {
          setErrors({ email: 'Enter a valid email address with a usable domain.' });
          document.getElementById('register-email')?.focus();
        } else if (field === 'password') {
          setErrors({ password: 'Meet all password requirements below.' });
          document.getElementById('register-password')?.focus();
        } else {
          setErrors({ form: 'Please review your account details and try again.' });
        }
      } else {
        setErrors({ form: 'Unable to create your account right now. Please try again.' });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthShell mode="register">
      {registered ? (
        <div className="auth-complete" role="status">
          <div className="auth-complete-icon"><Check size={30} aria-hidden="true" /></div>
          <span className="auth-eyebrow">ACCOUNT CREATED</span>
          <h1>Your workspace is ready.</h1>
          <p>Save this one-time recovery code in a safe place. It is shown only now and is required if you forget your password.</p>
          <div className="w-full rounded-xl border border-slate-300 bg-slate-50 p-4 my-4 text-left">
            <span className="block text-xs font-semibold text-slate-600 mb-2">Your recovery code</span>
            <code className="block break-all text-sm text-slate-900 select-all">{recoveryCode}</code>
          </div>
          <Button onClick={() => navigate('/login')} className="auth-submit">Continue to sign in <ArrowRight size={17} aria-hidden="true" /></Button>
        </div>
      ) : (
        <>
          <div className="auth-form-heading">
            <span className="auth-eyebrow">GET STARTED</span>
            <h1>Create your account</h1>
            <p>Start monitoring and investigating security events.</p>
          </div>
          {errors.form && <div className="auth-form-alert" role="alert">{errors.form}</div>}
          <form onSubmit={handleRegister} noValidate className="auth-form">
            <Input tone="dark" label="Full name" id="register-fullName" name="name" autoComplete="name"
              placeholder="Your full name" value={fullName} onChange={(event) => updateField('fullName', event.target.value, setFullName)}
              error={errors.fullName} icon={UserRound} required />
            <Input tone="dark" label="Email address" id="register-email" name="email" type="email" inputMode="email" autoComplete="email"
              placeholder="you@company.com" value={email} onChange={(event) => updateField('email', event.target.value, setEmail)}
              error={errors.email} icon={Mail} required />
            <Input tone="dark" label="Password" id="register-password" name="password" type={showPassword ? 'text' : 'password'} autoComplete="new-password"
              placeholder="Create a password" value={password} onChange={(event) => updateField('password', event.target.value, setPassword)}
              error={errors.password} icon={LockKeyhole} required aria-describedby="register-password-rules"
              rightIcon={showPassword ? EyeOff : Eye} rightActionLabel={showPassword ? 'Hide password' : 'Show password'}
              rightActionPressed={showPassword} onRightIconClick={() => setShowPassword((current) => !current)} />
            <div className="auth-password-rules" id="register-password-rules" aria-label="Password requirements">
              {passwordRules.map((rule) => (
                <span key={rule.label} className={password && rule.test(password) ? 'is-met' : ''}>
                  <Check size={13} aria-hidden="true" />{rule.label}
                </span>
              ))}
            </div>
            <Input tone="dark" label="Confirm password" id="register-confirmPassword" name="confirmPassword" type={showConfirmPassword ? 'text' : 'password'} autoComplete="new-password"
              placeholder="Re-enter your password" value={confirmPassword} onChange={(event) => updateField('confirmPassword', event.target.value, setConfirmPassword)}
              error={errors.confirmPassword} icon={LockKeyhole} required
              rightIcon={showConfirmPassword ? EyeOff : Eye} rightActionLabel={showConfirmPassword ? 'Hide password' : 'Show password'}
              rightActionPressed={showConfirmPassword} onRightIconClick={() => setShowConfirmPassword((current) => !current)} />
            <p className="text-xs text-slate-500">After registration, save the recovery code shown on the next screen. It replaces security questions.</p>
            <Button type="submit" isLoading={isLoading} className="auth-submit">
              {isLoading ? 'Creating account...' : 'Create account'}{!isLoading && <ArrowRight size={17} aria-hidden="true" />}
            </Button>
          </form>
          <p className="auth-switch">Already have an account? <Link to="/login" className="auth-link">Sign in</Link></p>
        </>
      )}
    </AuthShell>
  );
};

export default Register;
