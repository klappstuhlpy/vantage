// File sanitizer upload + history

(function() {
    'use strict';

    const dropZone = document.getElementById('san-drop-zone');
    const fileInput = document.getElementById('san-file-input');
    const progress = document.getElementById('san-progress');
    const progressBar = document.getElementById('san-progress-bar');
    const result = document.getElementById('san-result');
    const tbody = document.getElementById('san-tbody');
    const btnRefresh = document.getElementById('btn-refresh-history');

    // Load history on page load
    loadHistory();

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            uploadFile(e.target.files[0]);
        }
    });

    // Drag & drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            uploadFile(e.dataTransfer.files[0]);
        }
    });

    // Refresh button
    btnRefresh.addEventListener('click', loadHistory);

    async function uploadFile(file) {
        const maxSize = 16 * 1024 * 1024;
        if (file.size > maxSize) {
            showResult('error', 'File exceeds 16 MB limit.');
            return;
        }

        result.hidden = true;
        progress.hidden = false;
        progressBar.style.width = '0%';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round((e.loaded / e.total) * 100);
                    progressBar.style.width = pct + '%';
                }
            });

            xhr.addEventListener('load', () => {
                progress.hidden = true;
                if (xhr.status === 200) {
                    try {
                        const data = JSON.parse(xhr.responseText);
                        displayResult(data);
                        loadHistory();
                    } catch {
                        showResult('error', 'Failed to parse response.');
                    }
                } else {
                    try {
                        const err = JSON.parse(xhr.responseText);
                        showResult('error', err.error || 'Upload failed.');
                    } catch {
                        showResult('error', 'Upload failed with status ' + xhr.status);
                    }
                }
            });

            xhr.addEventListener('error', () => {
                progress.hidden = true;
                showResult('error', 'Network error during upload.');
            });

            xhr.open('POST', '/sanitizer/scan');
            xhr.send(formData);
        } catch (err) {
            progress.hidden = true;
            showResult('error', 'Upload failed: ' + err.message);
        }
    }

    function displayResult(data) {
        let verdict = 'unknown';
        if (data.clamav_clean === 0 || data.vt_status === 'detected') {
            verdict = 'infected';
        } else if (data.clamav_clean === 1 || data.vt_status === 'clean') {
            verdict = 'clean';
        }

        let verdictClass = 'result-unknown';
        let verdictText = 'Unknown';
        if (verdict === 'infected') {
            verdictClass = 'result-infected';
            verdictText = 'Infected';
        } else if (verdict === 'clean') {
            verdictClass = 'result-clean';
            verdictText = 'Clean';
        }

        let html = `<div class="san-result-verdict ${verdictClass}">${verdictText}</div>`;
        html += `<div class="san-result-row"><strong>File:</strong> ${escapeHtml(data.filename)}</div>`;
        html += `<div class="san-result-row"><strong>Size:</strong> ${formatBytes(data.file_size)}</div>`;
        html += `<div class="san-result-row"><strong>SHA-256:</strong> <code>${escapeHtml(data.sha256)}</code></div>`;

        if (data.clamav_clean !== null) {
            const status = data.clamav_clean === 1 ? 'Clean' : 'Infected';
            html += `<div class="san-result-row"><strong>ClamAV:</strong> ${status}`;
            if (data.clamav_virus) {
                html += ` — ${escapeHtml(data.clamav_virus)}`;
            }
            html += `</div>`;
        }

        if (data.vt_status) {
            html += `<div class="san-result-row"><strong>VirusTotal:</strong> ${escapeHtml(data.vt_status)}`;
            if (data.vt_positives !== null && data.vt_total !== null) {
                html += ` (${data.vt_positives}/${data.vt_total})`;
            }
            if (data.vt_url) {
                html += ` <a href="${escapeHtml(data.vt_url)}" target="_blank" rel="noopener">→ Report</a>`;
            }
            html += `</div>`;
        }

        result.innerHTML = html;
        result.hidden = false;
    }

    function showResult(type, message) {
        let verdictClass = type === 'error' ? 'result-infected' : 'result-unknown';
        result.innerHTML = `<div class="san-result-verdict ${verdictClass}">${escapeHtml(message)}</div>`;
        result.hidden = false;
    }

    async function loadHistory() {
        try {
            const res = await fetch('/sanitizer/history');
            if (!res.ok) throw new Error('Failed to load history');
            const data = await res.json();
            renderHistory(data.scans);
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="7" class="table-error">Failed to load history: ${escapeHtml(err.message)}</td></tr>`;
        }
    }

    function renderHistory(scans) {
        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No scans yet.</td></tr>';
            return;
        }

        tbody.innerHTML = scans.map(scan => {
            const clamavCell = scan.clamav_clean !== null
                ? (scan.clamav_clean === 1 ? '✓ Clean' : `✗ ${escapeHtml(scan.clamav_virus || 'Infected')}`)
                : '—';
            const vtCell = scan.vt_status
                ? `${escapeHtml(scan.vt_status)} ${scan.vt_positives !== null ? `(${scan.vt_positives}/${scan.vt_total})` : ''}`
                : '—';
            const scannedAt = new Date(scan.scanned_at).toLocaleString();

            return `
                <tr>
                    <td>${escapeHtml(scan.filename)}</td>
                    <td>${formatBytes(scan.file_size)}</td>
                    <td><code style="font-size:0.8em;">${escapeHtml(scan.sha256.substring(0, 16))}…</code></td>
                    <td>${clamavCell}</td>
                    <td>${vtCell}</td>
                    <td>${scannedAt}</td>
                    <td class="col-actions">
                        <button class="btn-icon" data-id="${scan.id}" title="Delete">×</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach delete handlers
        tbody.querySelectorAll('.btn-icon').forEach(btn => {
            btn.addEventListener('click', () => deleteScan(btn.dataset.id));
        });
    }

    async function deleteScan(id) {
        if (!confirm('Delete this scan record?')) return;
        try {
            const res = await fetch(`/sanitizer/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Delete failed');
            loadHistory();
        } catch (err) {
            alert('Failed to delete scan: ' + err.message);
        }
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
})();
