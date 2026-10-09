import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Send,
  RefreshCw,
  Zap,
  ShieldAlert,
  BarChart2,
  Network,
  FileSearch,
  MessageSquare,
  Bot,
  User,
  Trash2,
  ChevronRight,
  Activity,
  Lock
} from 'lucide-react';
import api from '../services/api';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeSanitize from 'rehype-sanitize';

// ────────────────────────────────────────────────────────────────────────────
// Markdown renderer for AI responses.
//
// Rendered with react-markdown (+ remark-gfm for tables) and hardened with
// rehype-sanitize. react-markdown never emits raw HTML from the source text,
// and the sanitizer strips any dangerous tags/attributes/URL schemes as a
// second layer — so attacker-influenced values echoed into an answer (uploaded
// filenames, source IPs, evidence parsed from log contents) cannot inject
// executable markup. Styling is applied through the component map, so no
// raw-HTML injection sink remains.
// ────────────────────────────────────────────────────────────────────────────
const markdownComponents = {
  h1: ({ children }) => <p className="text-sm font-bold text-slate-800 mb-2 mt-1">{children}</p>,
  h2: ({ children }) => <p className="text-sm font-bold text-slate-800 mb-2 mt-1">{children}</p>,
  h3: ({ children }) => <p className="text-xs font-bold text-slate-800 mb-1.5 mt-1">{children}</p>,
  p: ({ children }) => <p className="text-slate-700">{children}</p>,
  strong: ({ children }) => <strong className="text-slate-800 font-semibold">{children}</strong>,
  em: ({ children }) => <em className="italic text-slate-700">{children}</em>,
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="text-primary underline">
      {children}
    </a>
  ),
  code: ({ children }) => (
    <code className="bg-slate-100 px-1 py-0.5 rounded text-primary font-mono text-[10px]">{children}</code>
  ),
  ul: ({ children }) => <ul className="space-y-1.5">{children}</ul>,
  ol: ({ children }) => <ol className="space-y-1.5">{children}</ol>,
  li: ({ children }) => (
    <li className="flex gap-2 items-start">
      <span className="text-primary mt-0.5 shrink-0">›</span>
      <span className="text-slate-700 min-w-0">{children}</span>
    </li>
  ),
  hr: () => <hr className="border-slate-300/60 my-2" />,
  table: ({ children }) => (
    <div className="overflow-x-auto mt-2">
      <table className="w-full text-xs border-collapse">{children}</table>
    </div>
  ),
  tr: ({ children }) => <tr className="border-b border-slate-200/50">{children}</tr>,
  th: ({ children }) => (
    <th className="text-left py-1.5 px-2 text-slate-600 font-semibold text-[10px] uppercase tracking-wider border-b border-slate-300">
      {children}
    </th>
  ),
  td: ({ children }) => <td className="py-1.5 px-2 text-slate-700">{children}</td>,
};

const RenderMarkdown = ({ text }) => (
  <div className="space-y-1.5 text-xs leading-relaxed">
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      rehypePlugins={[rehypeSanitize]}
      components={markdownComponents}
    >
      {text}
    </ReactMarkdown>
  </div>
);

// ────────────────────────────────────────────────────────────────────────────
// Quick action prompts
// ────────────────────────────────────────────────────────────────────────────
const QUICK_PROMPTS = [
  { icon: BarChart2, label: 'Security Overview', prompt: 'Give me a security overview and summary of all threats' },
  { icon: Network, label: 'Suspicious IPs', prompt: 'Which IPs are most suspicious and what should I do about them?' },
  { icon: ShieldAlert, label: 'Active Incidents', prompt: 'How many active incidents are there? Show critical alerts.' },
  { icon: Zap, label: 'Brute Force', prompt: 'Analyze brute force attacks and give me response recommendations' },
  { icon: FileSearch, label: 'SQL Injection', prompt: 'Explain SQL injection threats detected and how to fix them' },
  { icon: Activity, label: 'Recommendations', prompt: 'What security actions do you recommend I take right now?' },
];

// ────────────────────────────────────────────────────────────────────────────
// Main Component
// ────────────────────────────────────────────────────────────────────────────
const AIAssistant = () => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      role: 'assistant',
      text: `## 👋 Hello! I'm your SecureSight AI Security Analyst\n\nI can analyze your security data and help you understand threats, investigate incidents, and recommend responses.\n\n**Try a quick action below or ask me anything about your security posture.**`,
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [conversationId, setConversationId] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [chatError, setChatError] = useState('');
  const [context, setContext] = useState({ stats: null });
  const [contextLoading, setContextLoading] = useState(true);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    let active = true;
    api.get('/api/assistant/conversations/latest')
      .then(({ data }) => {
        if (!active || !data) return;
        setConversationId(data.id);
        setMessages([...data.messages].sort((a, b) => a.id - b.id).map((message) => ({
          id: message.id,
          role: message.role,
          text: message.content,
          timestamp: new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(message.timestamp)
            ? message.timestamp : `${message.timestamp}Z`),
        })));
      })
      .catch(() => { if (active) setChatError('Could not load saved chat history.'); })
      .finally(() => { if (active) setHistoryLoading(false); });
    return () => { active = false; };
  }, []);

  // Fetch live context data on mount
  useEffect(() => {
    const loadContext = async () => {
      try {
        const statsRes = await api.get('/api/dashboard/stats');
        setContext({ stats: statsRes.data });
      } catch (err) {
        console.error('Failed to load AI context data', err);
      } finally {
        setContextLoading(false);
      }
    };
    loadContext();
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const sendMessage = async (text) => {
    const userText = text || input.trim();
    if (!userText || historyLoading) return;

    const userMsg = {
      id: Date.now(),
      role: 'user',
      text: userText,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    let responseText;
    try {
      const response = await api.post('/api/assistant/query', {
        message: userText,
        conversation_id: conversationId,
      }, { timeout: 35000 });
      responseText = response.data.answer;
      setConversationId(response.data.conversation_id);
    } catch (error) {
      responseText = `Assistant unavailable: ${error.response?.data?.detail || 'Please try again shortly.'}`;
    }


    const aiMsg = {
      id: Date.now() + 1,
      role: 'assistant',
      text: responseText,
      timestamp: new Date()
    };

    setIsTyping(false);
    setMessages(prev => [...prev, aiMsg]);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearChat = async () => {
    try {
      await api.delete('/api/assistant/conversations');
      setConversationId(null);
      setChatError('');
      setMessages([
      {
        id: Date.now(),
        role: 'assistant',
        text: `## 🔄 Chat cleared.\n\nHow can I help you with your security analysis today?`,
        timestamp: new Date()
      }
      ]);
    } catch {
      setChatError('Could not clear saved chat history. Please try again.');
    }
  };

  return (
    <div className="assistant-page flex flex-col max-w-5xl mx-auto h-[calc(100vh-130px)] min-h-[600px]">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex justify-between items-start mb-4 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2.5">
            <div className="p-1.5 bg-primary/15 rounded-lg border border-primary/25">
              <Sparkles size={20} className="text-primary" />
            </div>
            AI Security Assistant
          </h1>
          <p className="text-sm text-slate-9000 mt-1 ml-0.5">
            Contextual threat analysis powered by your live SIEM data.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Context status pill */}
          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-[10px] font-semibold ${
            contextLoading
              ? 'bg-slate-100 border-slate-300 text-slate-9000'
              : context.stats
              ? 'bg-success/10 border-success/25 text-success'
              : 'bg-warning/10 border-warning/25 text-warning'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${contextLoading ? 'bg-slate-500 animate-pulse' : context.stats ? 'bg-success' : 'bg-warning'}`} />
            {contextLoading ? 'Loading context...' : context.stats ? 'Live data connected' : 'No log data'}
          </div>
          <button
            onClick={clearChat}
            disabled={isTyping || historyLoading}
            className="p-2 rounded-lg bg-white border border-slate-200 text-slate-9000 hover:text-slate-800 hover:border-slate-300 transition-colors"
            title="Clear chat"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* ── Chat Container ──────────────────────────────────────────────── */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* Message Feed */}
        <div className="flex-1 flex flex-col bg-white border border-slate-200 rounded-2xl overflow-hidden">
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5 scroll-smooth">
            {chatError && <p className="text-xs text-danger" role="alert">{chatError}</p>}
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-8 h-8 rounded-full bg-primary/15 border border-primary/25 flex items-center justify-center shrink-0 mt-0.5">
                    <Bot size={14} className="text-primary" />
                  </div>
                )}
                <div
                  className={`max-w-[85%] rounded-2xl px-4 py-3.5 ${
                    msg.role === 'user'
                      ? 'bg-primary text-white rounded-tr-sm'
                      : 'bg-slate-50 border border-slate-200/80 rounded-tl-sm'
                  }`}
                >
                  {msg.role === 'user' ? (
                    <p className="text-xs font-medium leading-relaxed">{msg.text}</p>
                  ) : (
                    <RenderMarkdown text={msg.text} />
                  )}
                  <span className={`text-[9px] mt-2 block ${msg.role === 'user' ? 'text-blue-600 text-right' : 'text-slate-600'}`}>
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
                {msg.role === 'user' && (
                  <div className="w-8 h-8 rounded-full bg-slate-100 border border-slate-300 flex items-center justify-center shrink-0 mt-0.5">
                    <User size={14} className="text-slate-9000" />
                  </div>
                )}
              </div>
            ))}

            {/* Typing Indicator */}
            {isTyping && (
              <div className="flex gap-3 justify-start">
                <div className="w-8 h-8 rounded-full bg-primary/15 border border-primary/25 flex items-center justify-center shrink-0">
                  <Bot size={14} className="text-primary" />
                </div>
                <div className="bg-slate-50 border border-slate-200/80 rounded-2xl rounded-tl-sm px-4 py-3.5">
                  <div className="flex gap-1 items-center h-4">
                    <span className="w-1.5 h-1.5 rounded-full bg-primary/60 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-primary/60 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-primary/60 animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="border-t border-slate-200 p-4 bg-slate-100/20 shrink-0">
            {/* Quick Prompts */}
            <div className="flex flex-wrap gap-1.5 mb-3">
              {QUICK_PROMPTS.map((qp) => {
                const Icon = qp.icon;
                return (
                  <button
                    key={qp.label}
                    onClick={() => sendMessage(qp.prompt)}
                    disabled={isTyping || historyLoading}
                    className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-50 hover:bg-primary/10 border border-slate-200 hover:border-primary/30 rounded-full text-[10px] font-medium text-slate-9000 hover:text-primary transition-all duration-150 disabled:opacity-40"
                  >
                    <Icon size={10} />
                    {qp.label}
                  </button>
                );
              })}
            </div>

            {/* Message Input */}
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={isTyping || historyLoading}
                  placeholder="Ask about threats, IPs, incidents, attack explanations..."
                  rows={1}
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-500 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/30 resize-none transition-all duration-200 disabled:opacity-50 leading-relaxed"
                  style={{ minHeight: '40px', maxHeight: '120px' }}
                />
              </div>
              <button
                onClick={() => sendMessage()}
                disabled={!input.trim() || isTyping || historyLoading}
                className="px-4 py-2.5 bg-primary hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-xl transition-all duration-200 shadow-lg shadow-primary/20 flex items-center justify-center shrink-0"
              >
                {isTyping ? (
                  <RefreshCw size={16} className="animate-spin" />
                ) : (
                  <Send size={16} />
                )}
              </button>
            </div>
            <p className="text-[9px] text-slate-600 mt-2 text-center">
              Press Enter to send · Shift+Enter for new line · Responses use your live SIEM data
            </p>
          </div>
        </div>

        {/* ── Side Panel: Context Stats ──────────────────────────────── */}
        <div className="w-56 shrink-0 flex flex-col gap-3 hidden lg:flex">
          <div className="bg-white border border-slate-200 rounded-2xl p-4">
            <h3 className="text-[10px] font-bold text-slate-9000 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Activity size={11} /> Live Context
            </h3>
            {contextLoading ? (
              <div className="space-y-2">
                {[1,2,3,4].map(i => (
                  <div key={i} className="h-8 bg-slate-100 rounded-lg animate-pulse" />
                ))}
              </div>
            ) : context.stats ? (
              <div className="space-y-2">
                {[
                  { label: 'Log Events', value: context.stats.total_events?.toLocaleString(), color: 'text-info' },
                  { label: 'Total Threats', value: context.stats.total_threats, color: 'text-danger' },
                  { label: 'Active Alerts', value: context.stats.active_threats, color: 'text-warning' },
                  { label: 'Source Files', value: context.stats.total_files, color: 'text-success' },
                ].map((item, i) => (
                  <div key={i} className="flex justify-between items-center p-2 bg-slate-50/50 rounded-lg border border-slate-200/50">
                    <span className="text-[10px] text-slate-9000">{item.label}</span>
                    <span className={`text-xs font-bold ${item.color}`}>{item.value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 text-[10px] text-slate-9000">
                <Lock size={20} className="mx-auto mb-2 text-slate-700" />
                Upload logs to enable contextual AI responses
              </div>
            )}
          </div>

          {/* Capabilities */}
          <div className="bg-white border border-slate-200 rounded-2xl p-4 flex-1">
            <h3 className="text-[10px] font-bold text-slate-9000 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <MessageSquare size={11} /> What I Know
            </h3>
            <ul className="space-y-2 text-[10px] text-slate-9000">
              {[
                'Threat summaries',
                'Brute force analysis',
                'SQL injection review',
                'XSS attack analysis',
                'Suspicious IP hunting',
                'Incident response steps',
                'Security recommendations',
                'Attack definitions',
              ].map((item, i) => (
                <li key={i} className="flex items-center gap-1.5">
                  <ChevronRight size={10} className="text-primary/50 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIAssistant;
