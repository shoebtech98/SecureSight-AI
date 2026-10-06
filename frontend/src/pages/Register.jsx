import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Check, Eye, EyeOff, HelpCircle, LockKeyhole, Mail, UserRound } from 'lucide-react';
import api from '../services/api';
import Input from '../components/Input';
import Button from '../components/Button';
import AuthShell from '../components/AuthShell';

const SECURITY_QUESTIONS = [
  "What is your mother's maiden name?",
  'What was the name of your first pet?',
  'What was the name of your first school?',
  'In what city were you born?',
  'What is the brand of your first car?',
];
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
  const [securityQuestion, setSecurityQuestion] = useState(SECURITY_QUESTIONS[0]);
  const [securityAnswer, setSecurityAnswer] = useState('');
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
    if (!securityAnswer.trim()) nextErrors.securityAnswer = 'Enter an answer for account recovery.';
    else if (securityAnswer.length > 256) nextErrors.securityAnswer = 'Use 256 characters or fewer.';
    if (Object.keys(nextErrors).length) {
      setErrors(nextErrors);
      const first = ['fullName', 'email', 'password', 'confirmPassword', 'securityAnswer'].find((key) => nextErrors[key]);
      document.getElementById(`register-${first}`)?.focus();
      return;
    }

    setErrors({});
    setIsLoading(true);
    try {
      await api.post('/api/auth/register', {
        full_name: fullName.trim(), email: email.trim(), password,
        security_question: securityQuestion, security_answer: securityAnswer.trim(),
      });
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
        } else if (field === 'security_answer') {
          setErrors({ securityAnswer: 'Enter an answer using 256 characters or fewer.' });
          document.getElementById('register-securityAnswer')?.focus();
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
          <p>Your account has been created. Sign in to start monitoring your security events.</p>
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
            <div className="auth-recovery">
              <div className="auth-recovery-heading"><HelpCircle size={17} aria-hidden="true" /><span>Account recovery</span></div>
              <p>Your answer is used to reset your password if you lose access.</p>
              <label htmlFor="register-securityQuestion">Security question <span aria-hidden="true">*</span></label>
              <select id="register-securityQuestion" name="securityQuestion" value={securityQuestion} onChange={(event) => setSecurityQuestion(event.target.value)}>
                {SECURITY_QUESTIONS.map((question) => <option key={question} value={question}>{question}</option>)}
              </select>
              <Input tone="dark" label="Your answer" id="register-securityAnswer" name="securityAnswer" autoComplete="off"
                placeholder="Enter your answer" value={securityAnswer} onChange={(event) => updateField('securityAnswer', event.target.value, setSecurityAnswer)}
                error={errors.securityAnswer} required />
            </div>
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
