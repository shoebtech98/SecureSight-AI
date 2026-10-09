import React, { useState, useEffect } from 'react';
import { User, Mail, ShieldCheck, Lock, Save, KeyRound, Camera } from 'lucide-react';
import AvatarCropper from '../components/AvatarCropper';
import { getProfilePhoto, setProfilePhoto } from '../utils/profilePhoto';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import Alert from '../components/Alert';

const Profile = () => {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [createdAt, setCreatedAt] = useState('');
  const [profileImage, setProfileImage] = useState(null);
  const [userId, setUserId] = useState(null);
  const [cropFile, setCropFile] = useState(null);
  
  // Security Settings states
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [recoveryPassword, setRecoveryPassword] = useState('');
  const [hasRecoveryCode, setHasRecoveryCode] = useState(false);
  const [generatedRecoveryCode, setGeneratedRecoveryCode] = useState('');

  // Original values loaded from the server, used to detect *actual* changes so
  // we only demand the current password when a sensitive field really changes.
  const [initialEmail, setInitialEmail] = useState('');

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
        setHasRecoveryCode(Boolean(user.has_recovery_code));
        setUserId(user.id);
        setProfileImage(getProfilePhoto(user.id));
        
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
    const wantsSensitiveChange = Boolean(password) || email !== initialEmail;
    if (wantsSensitiveChange && !currentPassword) {
      setError('Enter your current password to change your email or password.');
      return;
    }

    setIsLoading(true);

    try {
      const initiatingToken = localStorage.getItem('token') || sessionStorage.getItem('token');
      const updatePayload = {
        full_name: fullName,
        email: email,
      };

      if (password) {
        updatePayload.password = password;
      }

      if (currentPassword) {
        updatePayload.current_password = currentPassword;
      }

      const response = await api.put('/api/auth/me', updatePayload);

      // Ignore a late response after logout or another login.
      if ((localStorage.getItem('token') || sessionStorage.getItem('token')) !== initiatingToken) return;
      if (response.data.access_token) {
        const storage = localStorage.getItem('token') ? localStorage : sessionStorage;
        storage.setItem('token', response.data.access_token);
      }

      setSuccess('Profile updated successfully!');

      // Reset the change-tracking baseline to the newly-saved values so saving
      // an unrelated field afterwards doesn't re-prompt for the password.
      setInitialEmail(email);

      // Clear password / re-auth inputs
      setPassword('');
      setConfirmPassword('');
      setCurrentPassword('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update profile.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRotateRecoveryCode = async () => {
    setError('');
    setSuccess('');
    if (!recoveryPassword) {
      setError('Enter your current password before creating a recovery code.');
      return;
    }
    setIsLoading(true);
    try {
      const initiatingToken = localStorage.getItem('token') || sessionStorage.getItem('token');
      const response = await api.post('/api/auth/recovery-code', { current_password: recoveryPassword });
      if ((localStorage.getItem('token') || sessionStorage.getItem('token')) !== initiatingToken) return;
      const storage = localStorage.getItem('token') ? localStorage : sessionStorage;
      storage.setItem('token', response.data.access_token);
      setGeneratedRecoveryCode(response.data.recovery_code);
      setHasRecoveryCode(true);
      setRecoveryPassword('');
      setSuccess('A new recovery code was created. Save it now; the previous code no longer works.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not create a recovery code.');
    } finally {
      setIsLoading(false);
    }
  };

  const saveAvatar = (imageData) => {
    setError('');
    try {
      setProfilePhoto(userId, imageData);
      setProfileImage(imageData);
      setCropFile(null);
      setSuccess(imageData ? 'Profile photo saved in this browser.' : 'Profile photo removed.');
    } catch { setError('Could not save the photo in this browser.'); }
  };

  return (
    <div className="settings-page mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Account settings</h1>
        <p className="text-xs text-slate-9000">View and update your personal details and security configuration</p>
      </div>

      {error && <Alert type="danger" message={error} onClose={() => setError('')} />}
      {success && <Alert type="success" message={success} onClose={() => setSuccess('')} />}

      <div className="settings-layout">
        <div className="settings-main-column">
          <section className="settings-form-card bg-white border border-slate-200 rounded-xl p-6">
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
                Required to change your email or password. Not needed for name-only edits.
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
          </section>
          <section className="settings-recovery-card bg-white border border-slate-200 rounded-xl p-6 space-y-3">
            <h3 className="text-sm font-semibold text-slate-800">Account recovery code</h3>
            <p className="text-xs text-slate-600">{hasRecoveryCode ? 'A recovery code is configured. Create a new one if you lost it; the previous code will stop working.' : 'No recovery code is configured yet. Create one while you are signed in.'}</p>
            <Input label="Current password to create a code" id="recoveryPassword" type="password" placeholder="••••••••" value={recoveryPassword} onChange={(event) => setRecoveryPassword(event.target.value)} icon={Lock} />
            {generatedRecoveryCode && (
              <div className="rounded-lg border border-amber-300 bg-amber-50 p-3" role="status">
                <p className="text-xs font-semibold text-amber-900 mb-2">Save this code now. It will not be shown again.</p>
                <code className="block break-all select-all text-sm text-slate-900">{generatedRecoveryCode}</code>
              </div>
            )}
            <Button type="button" onClick={handleRotateRecoveryCode} disabled={isLoading} icon={KeyRound}>Create new recovery code</Button>
          </section>
        </div>
        <aside className="settings-profile-card bg-white border border-slate-200 rounded-xl p-6 flex flex-col items-center text-center" aria-label="Profile summary">
          <div className="settings-avatar w-24 h-24 rounded-full bg-primary/20 border border-primary/40 flex items-center justify-center text-primary font-bold text-3xl mb-4">
            {profileImage ? <img src={profileImage} alt={`${fullName || 'User'} profile`} /> : fullName ? fullName.charAt(0).toUpperCase() : <User />}
          </div>
          <label className="settings-avatar-button"><Camera size={15} /> Add or change photo<input type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => { const next = event.target.files?.[0]; if (next) { if (next.size > 8 * 1024 * 1024) setError('Choose an image under 8 MB.'); else setCropFile(next); } event.target.value = ''; }} /></label>
          <p className="settings-photo-note">Photo is saved on this device only.</p>
          {profileImage && <button type="button" className="settings-avatar-remove" onClick={() => saveAvatar(null)}>Remove photo</button>}
          <h2 className="text-lg font-bold text-slate-800">{fullName}</h2>
          <p className="text-xs text-slate-9000 mt-0.5">{email}</p>
          <div className="mt-4 px-3 py-1 bg-slate-100/60 rounded text-[11px] font-semibold text-slate-700">Security Analyst</div>
          <div className="w-full border-t border-slate-200 mt-6 pt-6 text-left space-y-4">
            <div><p className="text-[10px] text-slate-9000 font-semibold tracking-wider uppercase">Account Created</p><p className="text-xs text-slate-700 mt-0.5">{createdAt || 'Loading...'}</p></div>
            <div><p className="text-[10px] text-slate-9000 font-semibold tracking-wider uppercase">Status</p><div className="flex items-center gap-1.5 mt-0.5 text-success text-xs font-medium"><ShieldCheck size={14} /> Active Session</div></div>
          </div>
        </aside>
      </div>
      {cropFile && <AvatarCropper file={cropFile} onCancel={() => setCropFile(null)} onSave={saveAvatar} />}
    </div>
  );
};

export default Profile;
