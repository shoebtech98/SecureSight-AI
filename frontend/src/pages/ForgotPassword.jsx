import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Mail, ArrowLeft, KeyRound, Lock } from 'lucide-react';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import Alert from '../components/Alert';
import ThemeToggle from '../components/ThemeToggle';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleResetPassword = async (event) => {
    event.preventDefault();
    setError('');
    if (newPassword !== confirmNewPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/\d/.test(newPassword) || !/[^A-Za-z0-9]/.test(newPassword) || new TextEncoder().encode(newPassword).length > 72) {
      setError('Use 8–72 bytes with uppercase, lowercase, a number, and a special character.');
      return;
    }
    setIsLoading(true);
    try {
      await api.post('/api/auth/reset-password', {
        email: email.trim(),
        recovery_code: recoveryCode.trim(),
        new_password: newPassword,
      });
      setSuccess('Password updated. Your recovery code has been used and all previous sessions have ended. Sign in to create a new code.');
      setRecoveryCode('');
      setNewPassword('');
      setConfirmNewPassword('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Reset failed. Check your email and recovery code.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-bg-main text-slate-800 px-4">
      <div className="fixed top-4 right-4 z-50"><ThemeToggle className="bg-white/70 border border-slate-200/80 shadow-sm" /></div>
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-primary/10 rounded-full filter blur-3xl pointer-events-none" />
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-8 shadow-2xl relative z-10">
        <Link to="/login" className="inline-flex items-center text-xs text-slate-600 hover:text-slate-800 mb-6 transition-colors">
          <ArrowLeft size={14} className="mr-1" /> Back to Sign In
        </Link>
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="p-3 bg-warning/10 rounded-2xl border border-warning/20 mb-3 text-warning"><KeyRound size={32} /></div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-800">Account Recovery</h1>
          <p className="text-sm text-slate-600 mt-1">Use the recovery code saved when your account was created. Each code works only once.</p>
        </div>
        {error && <Alert type="danger" message={error} onClose={() => setError('')} className="mb-5" />}
        {success && <Alert type="success" message={success} className="mb-5" />}
        {success ? (
          <Link to="/login" className="block text-center text-sm font-semibold text-primary">Continue to sign in</Link>
        ) : (
          <form onSubmit={handleResetPassword} className="space-y-4">
            <Input label="Email address" id="email" type="email" autoComplete="email" placeholder="name@company.com" value={email} onChange={(e) => setEmail(e.target.value)} required icon={Mail} />
            <Input label="Recovery code" id="recoveryCode" autoComplete="off" placeholder="Paste your saved recovery code" value={recoveryCode} onChange={(e) => setRecoveryCode(e.target.value)} required icon={KeyRound} />
            <Input label="New password" id="newPassword" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required icon={Lock} />
            <Input label="Confirm new password" id="confirmNewPassword" type="password" autoComplete="new-password" value={confirmNewPassword} onChange={(e) => setConfirmNewPassword(e.target.value)} required icon={Lock} />
            <Button type="submit" isLoading={isLoading} className="w-full mt-4">Reset Password</Button>
            <p className="text-xs text-slate-500">If you had an account before recovery codes were introduced, sign in and create a code in Profile. If you no longer know your password, contact the project administrator.</p>
          </form>
        )}
      </div>
    </div>
  );
};

export default ForgotPassword;
