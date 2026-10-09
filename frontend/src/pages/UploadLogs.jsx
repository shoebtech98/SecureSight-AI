import React, { useState, useEffect } from 'react';
import { File, Trash2, CheckCircle2, XCircle, RefreshCw } from 'lucide-react';
import api from '../services/api';
import Button from '../components/Button';
import Alert from '../components/Alert';
import { formatUtcDateTime } from '../utils/datetime';
import UploadFolder from '../components/UploadFolder';

const UploadLogs = () => {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadPhase, setUploadPhase] = useState('uploading');
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchFiles = async () => {
    setLoadingFiles(true);
    try {
      const response = await api.get('/api/logs/files');
      setUploadedFiles(response.data);
    } catch (err) {
      console.error('Failed to load uploaded files', err);
    } finally {
      setLoadingFiles(false);
    }
  };

  // Large files are parsed synchronously by the backend, which can exceed the
  // default 10s axios timeout. Give ingestion room to finish.
  const UPLOAD_TIMEOUT_MS = 10 * 60 * 1000;

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setUploadProgress(0);
    setUploadPhase('uploading');
    setError('');
    setSuccess('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      await api.post('/api/logs/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        timeout: UPLOAD_TIMEOUT_MS,
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percent = Math.min(100, Math.round((progressEvent.loaded / progressEvent.total) * 100));
            setUploadProgress(percent);
            if (percent >= 100) setUploadPhase('processing');
          }
        },
      });
      setSuccess(`File "${file.name}" ingested and parsed successfully!`);
      setFile(null);
      setUploadProgress(0);
      fetchFiles();
    } catch (err) {
      setError(
        err.response?.data?.detail || 'Failed to upload and parse the log file. Please check format.'
      );
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteFile = async (id) => {
    if (!window.confirm("Are you sure you want to delete this log file and all its associated events/alerts?")) {
      return;
    }
    
    try {
      await api.delete(`/api/logs/files/${id}`);
      setUploadedFiles(uploadedFiles.filter(f => f.id !== id));
      setSuccess("Log file deleted successfully.");
    } catch {
      setError("Failed to delete log file.");
    }
  };

  return (
    <div className="upload-page space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Upload Logs</h1>
        <p className="text-sm text-slate-9000 mt-1">
          Upload application logs, SSH log outputs, or web server access logs to parse events and run real-time threat analysis.
        </p>
      </div>

      {error && <Alert type="danger" message={error} onClose={() => setError('')} />}
      {success && <Alert type="success" message={success} onClose={() => setSuccess('')} />}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Container */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-6 flex flex-col">
          <h2 className="text-sm font-semibold text-slate-800 mb-4">Ingest New Log File</h2>

          <form onSubmit={handleUpload} className="flex-1 flex flex-col">
            <div
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              className={`flex-1 min-h-[220px] border-2 border-dashed rounded-xl flex flex-col items-center justify-center p-6 text-center cursor-pointer transition-all duration-200 ${
                dragActive
                  ? 'border-primary bg-primary/5'
                  : 'border-slate-200 hover:border-slate-300 hover:bg-slate-100/20'
              }`}
              onClick={() => document.getElementById('log-file-input').click()}
            >
              <input
                id="log-file-input"
                type="file"
                className="hidden"
                accept=".log,.txt,.csv,.json"
                onChange={handleFileChange}
              />
              
              <UploadFolder />
              
              {file ? (
                <div className="space-y-1">
                  <p className="text-sm font-semibold text-slate-800">{file.name}</p>
                  <p className="text-xs text-slate-9000">{formatBytes(file.size)}</p>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <p className="text-sm font-semibold text-slate-800">Drag & drop your log file here</p>
                  <p className="text-xs text-slate-9000">or click to browse from your device</p>
                  <p className="text-[10px] text-slate-9000 font-mono mt-2">Supports .log, .txt, .csv, .json (Apache, Nginx, SSH auth.log, standard syslogs, Suricata JSON, CSV exports)</p>
                </div>
              )}
            </div>

            {file && (
              <div className="mt-4 space-y-3">
                {/* Upload / parse progress bar */}
                {uploading && (
                  <div className="bg-slate-50 border border-slate-200 rounded-xl px-4 py-3">
                    <div className="flex justify-between items-center text-[10px] font-semibold text-slate-500 mb-1.5">
                      <span className="flex items-center gap-1.5">
                        <RefreshCw size={11} className="animate-spin text-primary" />
                        {uploadPhase === 'uploading'
                          ? `Uploading “${file.name}”…`
                          : 'Upload complete. Parsing events & running threat detection…'}
                      </span>
                      <span className="font-mono text-slate-800">
                        {uploadPhase === 'uploading' ? `${uploadProgress}% sent` : 'Processing'}
                      </span>
                    </div>
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden" role="progressbar"
                      aria-label={uploadPhase === 'uploading' ? 'File upload' : 'Server processing'}
                      aria-valuenow={uploadPhase === 'uploading' ? uploadProgress : undefined}
                      aria-valuemin={uploadPhase === 'uploading' ? 0 : undefined}
                      aria-valuemax={uploadPhase === 'uploading' ? 100 : undefined}>
                      <div
                        className={`h-full rounded-full transition-all duration-200 ${uploadPhase === 'processing' ? 'w-1/3 bg-primary animate-pulse' : 'bg-primary'}`}
                        style={uploadPhase === 'uploading' ? { width: `${Math.max(uploadProgress, 4)}%` } : undefined}
                      />
                    </div>
                  </div>
                )}

                <div className="flex gap-3 justify-end">
                  <Button
                    variant="secondary"
                    type="button"
                    onClick={() => setFile(null)}
                    disabled={uploading}
                    className="px-4 py-2 text-xs"
                  >
                    Clear Selection
                  </Button>
                  <Button
                    type="submit"
                    isLoading={uploading}
                    className="px-5 py-2 text-xs"
                  >
                    {uploading ? 'Processing…' : 'Parse & Ingest Log'}
                  </Button>
                </div>
              </div>
            )}
          </form>
        </div>

        {/* Info Column */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-slate-800 mb-3">Supported Formats & Rules</h2>
          <ul className="space-y-3.5 text-xs text-slate-9000">
            <li className="flex gap-2.5">
              <span className="w-1.5 h-1.5 bg-primary rounded-full mt-1.5 shrink-0" />
              <div>
                <strong className="text-slate-800 block mb-0.5">SSH Auth Logs (auth.log)</strong>
                Processes sshd entries for logins. Raises <strong className="text-danger">Brute Force</strong> alerts if 5+ failed attempts occur from the same IP.
              </div>
            </li>
            <li className="flex gap-2.5">
              <span className="w-1.5 h-1.5 bg-info rounded-full mt-1.5 shrink-0" />
              <div>
                <strong className="text-slate-800 block mb-0.5">Nginx / Apache Web Logs</strong>
                Combined common request format. Scans for <strong className="text-danger">SQL Injection</strong> and <strong className="text-danger">XSS</strong> injection payload patterns.
              </div>
            </li>
            <li className="flex gap-2.5">
              <span className="w-1.5 h-1.5 bg-success rounded-full mt-1.5 shrink-0" />
              <div>
                <strong className="text-slate-800 block mb-0.5">Directory Traversal</strong>
                Flags directory traversal parameters (e.g. `../etc/passwd`) or intense scanner scans (10+ 404 responses from one IP).
              </div>
            </li>
          </ul>
          <p className="event-data-note mt-5">Source IPs and event timestamps are read from uploaded records when present and recognized. Missing values are not generated.</p>
        </div>
      </div>

      {/* Uploaded Files Table */}
      <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
          <h2 className="text-sm font-semibold text-slate-800">Ingested Log Source files</h2>
          <button
            onClick={fetchFiles}
            disabled={loadingFiles}
            className="p-1.5 rounded-lg text-slate-9000 hover:bg-slate-50 hover:text-slate-800 transition-colors"
          >
            <RefreshCw size={14} className={loadingFiles ? 'animate-spin' : ''} />
          </button>
        </div>

        {loadingFiles ? (
          <div className="py-12 text-center text-xs text-slate-9000">
            Loading ingested database records...
          </div>
        ) : uploadedFiles.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-9000 flex flex-col items-center gap-2">
            <File size={36} className="text-slate-700 stroke-[1.5]" />
            No logs have been ingested yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-100/30 text-slate-9000 uppercase tracking-wider text-[10px]">
                  <th className="px-6 py-3.5 font-semibold">Filename</th>
                  <th className="px-6 py-3.5 font-semibold">Size</th>
                  <th className="px-6 py-3.5 font-semibold">Ingestion Time</th>
                  <th className="px-6 py-3.5 font-semibold">Status</th>
                  <th className="px-6 py-3.5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {uploadedFiles.map((file) => (
                  <tr key={file.id} className="hover:bg-slate-100/20 text-slate-700">
                    <td className="px-6 py-3.5 font-medium text-slate-800">{file.filename}</td>
                    <td className="px-6 py-3.5">{formatBytes(file.file_size)}</td>
                    <td className="px-6 py-3.5">
                      {formatUtcDateTime(file.uploaded_at)}
                    </td>
                    <td className="px-6 py-3.5">
                      {file.status === 'parsed' && (
                        <span className="inline-flex items-center gap-1.5 text-success font-semibold">
                          <CheckCircle2 size={12} /> Parsed
                        </span>
                      )}
                      {file.status === 'processing' && (
                        <span className="inline-flex items-center gap-1.5 text-warning font-semibold animate-pulse">
                          <RefreshCw size={12} className="animate-spin" /> Ingesting...
                        </span>
                      )}
                      {file.status === 'failed' && (
                        <span className="inline-flex items-center gap-1.5 text-danger font-semibold" title={file.error_message}>
                          <XCircle size={12} /> Ingestion Failed
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-3.5 text-right">
                      <button
                        onClick={() => handleDeleteFile(file.id)}
                        className="p-1.5 text-danger hover:bg-red-500/10 rounded-lg transition-colors inline-flex items-center"
                        title="Delete log file and related statistics"
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default UploadLogs;
