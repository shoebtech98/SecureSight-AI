import { Activity, ArrowUpRight, LockKeyhole, ShieldCheck } from 'lucide-react';

const AuthShell = ({ children, mode }) => (
  <main className={`auth-page auth-page--${mode}`}>
    <section className="auth-story" aria-labelledby="auth-story-title">
      <div className="auth-story-inner">
        <div className="auth-brand"><span className="auth-brand-mark"><ShieldCheck size={23} strokeWidth={1.8} aria-hidden="true" /></span><span>SecureSight <strong>AI</strong></span></div>
        <div className="auth-story-main">
          <div className="auth-story-kicker"><span className="auth-live-dot" /> SECURITY OPERATIONS, MADE CLEAR</div>
          <div id="auth-story-title" className="auth-story-headline">Secure your logs.<br /><em>Understand your threats.</em></div>
          <p>Monitor security events, detect threats, and investigate incidents with intelligent security analytics.</p>
          <div className="auth-flow" aria-label="SecureSight workflow">
            <span>01 <strong>Upload logs</strong></span><i />
            <span>02 <strong>Detect threats</strong></span><i />
            <span>03 <strong>Investigate</strong></span>
          </div>
          <div className="auth-visual" aria-hidden="true">
            <div className="auth-visual-head"><span><Activity size={15} /> EVENT ANALYSIS</span><span>● ● ●</span></div>
            <div className="auth-visual-body">
              <div className="auth-visual-line"><span className="auth-visual-index">01</span><span className="auth-visual-bars"><b /><b /><b /></span><span className="auth-visual-pill">PARSED</span></div>
              <div className="auth-visual-line"><span className="auth-visual-index">02</span><span className="auth-visual-bars"><b /><b /><b /></span><span className="auth-visual-pill auth-visual-pill--amber">CORRELATED</span></div>
              <div className="auth-visual-line"><span className="auth-visual-index">03</span><span className="auth-visual-bars"><b /><b /><b /></span><span className="auth-visual-pill">REVIEWED</span></div>
            </div>
            <div className="auth-visual-caption"><LockKeyhole size={13} /> Your security workspace <ArrowUpRight size={14} /></div>
          </div>
        </div>
        <p className="auth-story-footer">SECURESIGHT AI <span>•</span> SECURITY ANALYTICS WORKSPACE</p>
      </div>
    </section>
    <section className="auth-access" aria-label="Account access">
      <div className="auth-mobile-brand"><span className="auth-brand-mark"><ShieldCheck size={21} aria-hidden="true" /></span> SecureSight <strong>AI</strong></div>
      <div className="auth-card">{children}</div>
      <p className="auth-access-footer">SecureSight AI <span>·</span> Security analytics workspace</p>
    </section>
  </main>
);

export default AuthShell;
