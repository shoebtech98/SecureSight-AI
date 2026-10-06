import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ArrowRight, Eye, EyeOff, LockKeyhole, Mail } from 'lucide-react';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import AuthShell from '../components/AuthShell';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);

  const updateField = (field, value, setter) => {
    setter(value);
    setErrors((current) => ({ ...current, [field]: undefined, form: undefined }));
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    if (isLoading) return;
    const nextErrors = {};
    if (!email.trim()) nextErrors.email = 'Enter your email address.';
    else if (!EMAIL_PATTERN.test(email.trim())) nextErrors.email = 'Enter a valid email address.';
    if (!password) nextErrors.password = 'Enter your password.';
    if (Object.keys(nextErrors).length) {
      setErrors(nextErrors);
      document.getElementById(nextErrors.email ? 'login-email' : 'login-password')?.focus();
      return;
    }

    setErrors({});
    setIsLoading(true);
    try {
      const response = await api.post(`/api/auth/login?remember_me=${rememberMe}`, { email: email.trim(), password });
      const storage = rememberMe ? localStorage : sessionStorage;
      const otherStorage = rememberMe ? sessionStorage : localStorage;
      otherStorage.removeItem('token');
      storage.setItem('token', response.data.access_token);
      const requested = location.state?.from;
      const destination = requested?.pathname?.startsWith('/') && !requested.pathname.startsWith('//')
        ? `${requested.pathname}${requested.search || ''}${requested.hash || ''}`
        : '/';
      navigate(destination, { replace: true });
    } catch (error) {
      if (error.response?.status === 401) {
        setErrors({ password: 'Email or password is incorrect.' });
        document.getElementById('login-password')?.focus();
      } else if (error.response?.status === 429) {
        setErrors({ form: 'Too many sign-in attempts. Please try again shortly.' });
      } else {
        setErrors({ form: 'Unable to sign in right now. Please try again.' });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthShell mode="login">
      <div className="auth-form-heading">
        <span className="auth-eyebrow">SECURE ACCESS</span>
        <h1>Welcome back</h1>
        <p>Sign in to your SecureSight workspace.</p>
      </div>
      {errors.form && <div className="auth-form-alert" role="alert">{errors.form}</div>}
      <form onSubmit={handleLogin} noValidate className="auth-form">
        <Input tone="dark" label="Email address" id="login-email" name="email" type="email" autoComplete="email" inputMode="email"
          placeholder="you@company.com" value={email} onChange={(event) => updateField('email', event.target.value, setEmail)}
          error={errors.email} icon={Mail} required />
        <Input tone="dark" label="Password" id="login-password" name="password" type={showPassword ? 'text' : 'password'}
          autoComplete="current-password" placeholder="Enter your password" value={password}
          onChange={(event) => updateField('password', event.target.value, setPassword)} error={errors.password}
          icon={LockKeyhole} required rightIcon={showPassword ? EyeOff : Eye}
          rightActionLabel={showPassword ? 'Hide password' : 'Show password'} rightActionPressed={showPassword}
          onRightIconClick={() => setShowPassword((current) => !current)} />
        <div className="auth-form-options">
          <label className="auth-checkbox-label">
            <input type="checkbox" name="rememberMe" checked={rememberMe} onChange={(event) => setRememberMe(event.target.checked)} />
            <span>Remember me</span>
          </label>
          <Link to="/forgot-password" className="auth-link">Forgot password?</Link>
        </div>
        <Button type="submit" isLoading={isLoading} className="auth-submit">
          {isLoading ? 'Signing in...' : 'Sign in'}{!isLoading && <ArrowRight size={17} aria-hidden="true" />}
        </Button>
      </form>
      <p className="auth-switch">New to SecureSight? <Link to="/register" className="auth-link">Create an account</Link></p>
    </AuthShell>
  );
};

export default Login;
