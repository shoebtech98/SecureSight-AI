import React, { useState, useEffect } from 'react';
import { User, Mail, ShieldCheck, Lock, HelpCircle, Save } from 'lucide-react';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import Alert from '../components/Alert';

const SECURITY_QUESTIONS = [
  'What is your mother\'s maiden name?',
  'What was the name of your first pet?',
  'What was the name of your first school?',
  'In what city were you born?',
  'What is the brand of your first car?',
];

const Profile = () => {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [createdAt, setCreatedAt] = useState('');
  
  // Security Settings states
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState(SECURITY_QUESTIONS[0]);
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');

  // Original values loaded from the server, used to detect *actual* changes so
  // we only demand the current password when a sensitive field really changes.
  const [initialEmail, setInitialEmail] = useState('');
  const [initialSecurityQuestion, setInitialSecurityQuestion] = useState('');

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await api.get('/api/auth/me');
        const user = response.data;
        setFullName(user.full_name);
        setEmail(user.email);
        setInitialEmail(user.email);
        const loadedQuestion = user.security_question || SECURITY_QUESTIONS[0];
        setSecurityQuestion(loadedQuestion);
        setInitialSecurityQuestion(loadedQuestion);
        
        // Format creation date
        if (user.created_at) {
          const date = new Date(user.created_at);
          setCreatedAt(date.toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          }));
        }
      } catch {
        setError('Failed to load profile details.');
      }
    };
    fetchUserData();
  }, []);

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (password && password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password && (password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password))) {
      setError('New password must include uppercase, lowercase, a number, and a special character (min 8 chars)');
      return;
    }

    // Changing a credential or recovery factor requires re-entering the current
    // password. The backend enforces this too (defense in depth); this check is
    // just for a clearer message before the round-trip.
    const wantsSensitiveChange =
      Boolean(password) ||
      Boolean(securityAnswer) ||
      email !== initialEmail ||
      securityQuestion !== initialSecurityQuestion;
    if (wantsSensitiveChange && !currentPassword) {
      setError('Enter your current password to change your email, password, or security question/answer.');
      return;
    }

    setIsLoading(true);

    try {
      const updatePayload = {
        full_name: fullName,
        email: email,
      };

      if (password) {
        updatePayload.password = password;
      }

      if (securityQuestion) {
        updatePayload.security_question = securityQuestion;
      }

      if (securityAnswer) {
        updatePayload.security_answer = securityAnswer;
      }

      if (currentPassword) {
        updatePayload.current_password = currentPassword;
      }

      const response = await api.put('/api/auth/me', updatePayload);

      // Changing the email re-issues the JWT on the backend; persist the new
      // token so the session does not appear to end unexpectedly.
      if (response.data.access_token) {
        const storage = localStorage.getItem('token') ? localStorage : sessionStorage;
        storage.setItem('token', response.data.access_token);
      }

      setSuccess('Profile updated successfully!');

      // Reset the change-tracking baseline to the newly-saved values so saving
      // an unrelated field afterwards doesn't re-prompt for the password.
      setInitialEmail(email);
      setInitialSecurityQuestion(securityQuestion);

      // Clear password / re-auth inputs
      setPassword('');
      setConfirmPassword('');
      setSecurityAnswer('');
      setCurrentPassword('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update profile.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">User Profile</h1>
        <p className="text-xs text-slate-9000">View and update your personal details and security configuration</p>
      </div>

      {error && <Alert type="danger" message={error} onClose={() => setError('')} />}
      {success && <Alert type="success" message={success} onClose={() => setSuccess('')} />}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Left Card: Summary */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 flex flex-col items-center text-center">
          <div className="w-24 h-24 rounded-full bg-primary/20 border border-primary/40 flex items-center justify-center text-primary font-bold text-3xl mb-4">
            {fullName ? fullName.charAt(0).toUpperCase() : <User />}
          </div>
          <h2 className="text-lg font-bold text-slate-800">{fullName}</h2>
          <p className="text-xs text-slate-9000 mt-0.5">{email}</p>
          <div className="mt-4 px-3 py-1 bg-slate-100/60 rounded text-[11px] font-semibold text-slate-700">
            System Administrator
          </div>
          
          <div className="w-full border-t border-slate-200 mt-6 pt-6 text-left space-y-4">
            <div>
              <p className="text-[10px] text-slate-9000 font-semibold tracking-wider uppercase">Account Created</p>
              <p className="text-xs text-slate-700 mt-0.5">{createdAt || 'Loading...'}</p>
            </div>
            <div>
              <p className="text-[10px] text-slate-9000 font-semibold tracking-wider uppercase">Status</p>
              <div className="flex items-center gap-1.5 mt-0.5 text-success text-xs font-medium">
                <ShieldCheck size={14} /> Active Session
              </div>
            </div>
          </div>
        </div>

        {/* Right Form: Settings */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 md:col-span-2">
          <form onSubmit={handleUpdateProfile} className="space-y-6">
            <div>
              <h3 className="text-sm font-semibold text-slate-800 border-b border-slate-200 pb-2 mb-4">
                Personal Details
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <Input
                  label="Full Name"
                  id="fullName"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required
                  icon={User}
                />
                <Input
                  label="Email address"
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  icon={Mail}
                />
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-slate-800 border-b border-slate-200 pb-2 mb-4">
                Change Password (optional)
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <Input
                  label="New Password"
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  icon={Lock}
                />
                <Input
                  label="Confirm New Password"
                  id="confirmPassword"
                  type="password"
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  icon={Lock}
                />
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-slate-800 border-b border-slate-200 pb-2 mb-4">
                Update Recovery Question
              </h3>
              <div className="mb-4">
                <label htmlFor="securityQuestion" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Security Question
                </label>
                <div className="relative rounded-lg shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-9000">
                    <HelpCircle size={18} />
                  </div>
                  <select
                    id="securityQuestion"
                    value={securityQuestion}
                    onChange={(e) => setSecurityQuestion(e.target.value)}
                    className="block w-full rounded-lg bg-white border border-slate-300 pl-10 pr-3 py-2.5 text-slate-800 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all duration-200 text-sm appearance-none cursor-pointer"
                  >
                    {SECURITY_QUESTIONS.map((q, i) => (
                      <option key={i} value={q}>
                        {q}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <Input
                label="Security Answer (Leave blank to keep current)"
                id="securityAnswer"
                placeholder="Enter new recovery answer"
                value={securityAnswer}
                onChange={(e) => setSecurityAnswer(e.target.value)}
                icon={ShieldCheck}
              />
            </div>

            <div>
              <h3 className="text-sm font-semibold text-slate-800 border-b border-slate-200 pb-2 mb-4">
                Confirm Changes
              </h3>
              <Input
                label="Current Password"
                id="currentPassword"
                type="password"
                placeholder="••••••••"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                icon={Lock}
              />
              <p className="text-[11px] text-slate-500 mt-1.5">
                Required to change your email, password, or security question/answer. Not needed for name-only edits.
              </p>
            </div>

            <div className="flex justify-end pt-2">
              <Button
                type="submit"
                isLoading={isLoading}
                icon={Save}
              >
                Save Settings
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Profile;
