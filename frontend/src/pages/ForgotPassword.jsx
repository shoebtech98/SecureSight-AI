import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Mail, ArrowLeft, KeyRound, HelpCircle, Lock } from 'lucide-react';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import Alert from '../components/Alert';
import ThemeToggle from '../components/ThemeToggle';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [step, setStep] = useState(1); // Step 1: Request Email, Step 2: Answer Question & Reset Password
  const [securityQuestion, setSecurityQuestion] = useState('');
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const navigate = useNavigate();

  const handleFetchQuestion = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await api.post('/api/auth/forgot-password', { email });
      setSecurityQuestion(response.data.security_question);
      setStep(2);
    } catch (err) {
      setError(
        err.response?.data?.detail || 'Failed to fetch recovery options. Please check your email.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (newPassword !== confirmNewPassword) {
      setError('Passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }
    if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/\d/.test(newPassword) || !/[^A-Za-z0-9]/.test(newPassword)) {
      setError('Password must include uppercase, lowercase, a number, and a special character');
      return;
    }

    setIsLoading(true);

    try {
      await api.post('/api/auth/reset-password', {
        email,
        security_answer: securityAnswer,
        new_password: newPassword,
      });

      setSuccess('Password updated successfully! Redirecting to login...');
      setTimeout(() => {
        navigate('/login');
      }, 1500);
    } catch (err) {
      setError(
        err.response?.data?.detail || 'Reset failed. Ensure the security answer is correct.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-bg-main text-slate-800 px-4">
      {/* Theme Toggle */}
      <div className="fixed top-4 right-4 z-50">
        <ThemeToggle className="bg-white/70 border border-slate-200/80 shadow-sm" />
      </div>
      {/* Decorative background glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-primary/10 rounded-full filter blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-8 shadow-2xl relative z-10">
        {/* Back Link */}
        <Link
          to="/login"
          className="inline-flex items-center text-xs text-slate-9000 hover:text-slate-800 mb-6 transition-colors"
        >
          <ArrowLeft size={14} className="mr-1" /> Back to Sign In
        </Link>

        {/* Header */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="p-3 bg-warning/10 rounded-2xl border border-warning/20 mb-3 text-warning">
            <KeyRound size={32} />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-800">
            Account Recovery
          </h1>
          <p className="text-sm text-slate-9000 mt-1">
            {step === 1
              ? 'Enter your email to retrieve your security challenge'
              : 'Answer the challenge question to reset your password'}
          </p>
        </div>

        {error && <Alert type="danger" message={error} onClose={() => setError('')} className="mb-5" />}
        {success && <Alert type="success" message={success} className="mb-5" />}

        {step === 1 ? (
          <form onSubmit={handleFetchQuestion} className="space-y-4">
            <Input
              label="Email address"
              id="email"
              type="email"
              placeholder="name@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              icon={Mail}
            />

            <Button
              type="submit"
              isLoading={isLoading}
              className="w-full mt-2"
            >
              Get Security Challenge
            </Button>
          </form>
        ) : (
          <form onSubmit={handleResetPassword} className="space-y-4">
            {/* Display security question as text */}
            <div className="bg-slate-50/50 border border-slate-300/60 p-4.5 rounded-lg mb-2">
              <div className="flex items-start gap-2.5">
                <HelpCircle size={18} className="text-primary mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs text-slate-9000 font-semibold tracking-wider uppercase mb-1">Challenge Question</p>
                  <p className="text-sm font-medium text-slate-800">{securityQuestion}</p>
                </div>
              </div>
            </div>

            <Input
              label="Your Answer"
              id="securityAnswer"
              placeholder="Enter challenge answer"
              value={securityAnswer}
              onChange={(e) => setSecurityAnswer(e.target.value)}
              required
              icon={KeyRound}
            />

            <Input
              label="New Password"
              id="newPassword"
              type="password"
              placeholder="••••••••"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              icon={Lock}
            />

            <Input
              label="Confirm New Password"
              id="confirmNewPassword"
              type="password"
              placeholder="••••••••"
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              required
              icon={Lock}
            />

            <Button
              type="submit"
              isLoading={isLoading}
              className="w-full mt-4"
            >
              Reset Password
            </Button>
          </form>
        )}
      </div>
    </div>
  );
};

export default ForgotPassword;
