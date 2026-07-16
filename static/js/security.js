// Security analytics dashboard
(function() {
    'use strict';

    let currentRange = '24h';
    let timelineChart = null;
    let cfChart = null;

    const FLAGS = window.SECURITY_FLAGS || { geoipEnabled: false, cloudflareEnabled: false };

    // ─── Range picker ───────────────────────────────────────────────

    document.getElementById('range-picker')?.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON') {
            currentRange = e.target.dataset.range;
            document.querySelectorAll('#range-picker button').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            loadData();
        }
    });

    // ─── Data loading ───────────────────────────────────────────────

    async function loadData() {
        try {
            const res = await fetch(`/security/data?range=${currentRange}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            renderData(data);
        } catch (err) {
            console.error('Failed to load security data:', err);
        }

        if (FLAGS.cloudflareEnabled) {
            loadCloudflareData();
        }
    }

    async function loadCloudflareData() {
        try {
            const res = await fetch(`/security/cloudflare?range=${currentRange}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            renderCloudflareData(data);
        } catch (err) {
            console.error('Failed to load Cloudflare data:', err);
        }
    }

    // ─── Rendering ──────────────────────────────────────────────────

    function renderData(data) {
        // Headline tiles
        document.getElementById('tile-failed-logins').textContent = data.totals.failed_logins.toLocaleString();
        document.getElementById('tile-rate-limited').textContent = data.totals.rate_limited.toLocaleString();
        document.getElementById('tile-bad-requests').textContent = data.totals.bad_requests.toLocaleString();
        document.getElementById('tile-unique-ips').textContent = data.totals.unique_ips.toLocaleString();

        // Timeline chart
        renderTimeline(data.timeline);

        // Top IPs table
        renderTopIps(data.top_ips);

        // Reason breakdown
        renderReasonBreakdown(data.reason_breakdown);

        // Country distribution
        if (FLAGS.geoipEnabled) {
            renderCountryDistribution(data.country_distribution);
        }

        // Recent events
        renderRecentEvents(data.recent);
    }

    function renderTimeline(buckets) {
        if (!buckets.length) return;

        const data = [
            buckets.map(b => b.ts),
            buckets.map(b => b.failed_logins),
            buckets.map(b => b.rate_limited),
            buckets.map(b => b.bad_requests),
        ];

        const opts = {
            width: document.getElementById('chart-timeline').offsetWidth - 32,
            height: 250,
            series: [
                {},
                { label: 'Failed logins', stroke: '#d97757', width: 2 },
                { label: 'Rate limited', stroke: '#7ba2d9', width: 2 },
                { label: 'Bad requests', stroke: '#888', width: 1 },
            ],
            axes: [
                {},
                { scale: 'count' },
            ],
            scales: {
                x: { time: true },
                count: {},
            },
        };

        if (timelineChart) {
            timelineChart.setData(data);
        } else {
            timelineChart = new uPlot(opts, data, document.getElementById('chart-timeline'));
        }
    }

    function renderTopIps(ips) {
        const tbody = document.querySelector('#top-ips tbody');
        if (!ips.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="muted">No data</td></tr>';
            return;
        }

        tbody.innerHTML = ips.map(ip => {
            const cols = [
                `<td><code>${ip.ip}</code></td>`,
            ];
            if (FLAGS.geoipEnabled) {
                cols.push(`<td>${ip.country || '—'} ${ip.country_code ? `(${ip.country_code})` : ''}</td>`);
            }
            cols.push(`<td>${ip.count}</td>`);
            return `<tr>${cols.join('')}</tr>`;
        }).join('');
    }

    function renderReasonBreakdown(reasons) {
        const el = document.getElementById('reason-list');
        if (!reasons.length) {
            el.innerHTML = '<div class="muted">No data</div>';
            return;
        }

        const max = Math.max(...reasons.map(r => r.count));
        el.innerHTML = reasons.map(r => `
            <div class="reason-item">
                <div class="reason-label">${r.reason}</div>
                <div class="reason-bar" style="width: ${(r.count / max * 200)}px;"></div>
                <div class="reason-count">${r.count}</div>
            </div>
        `).join('');
    }

    function renderCountryDistribution(countries) {
        const el = document.getElementById('country-list');
        if (!el) return;
        if (!countries.length) {
            el.innerHTML = '<div class="muted">No data</div>';
            return;
        }

        const max = Math.max(...countries.map(c => c.count));
        el.innerHTML = countries.map(c => `
            <div class="country-item">
                <div class="country-label">${c.country_code} ${c.country}</div>
                <div class="country-bar" style="width: ${(c.count / max * 200)}px;"></div>
                <div class="country-count">${c.count}</div>
            </div>
        `).join('');
    }

    function renderRecentEvents(events) {
        const tbody = document.querySelector('#recent-events tbody');
        if (!events.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="muted">No data</td></tr>';
            return;
        }

        tbody.innerHTML = events.map(e => {
            const cols = [
                `<td>${new Date(e.ts * 1000).toLocaleString()}</td>`,
                `<td><code>${e.ip || '—'}</code></td>`,
            ];
            if (FLAGS.geoipEnabled) {
                cols.push(`<td>${e.country_code || '—'}</td>`);
            }
            cols.push(
                `<td>${e.status_code}</td>`,
                `<td>${e.reason}</td>`,
                `<td><code>${e.path}</code></td>`
            );
            return `<tr>${cols.join('')}</tr>`;
        }).join('');
    }

    function renderCloudflareData(data) {
        const { summary, events } = data;

        // CF tiles
        document.getElementById('cf-requests').textContent = summary.total_requests.toLocaleString();
        const cachedPct = summary.total_requests > 0
            ? ((summary.cached_requests / summary.total_requests) * 100).toFixed(1)
            : '0';
        document.getElementById('cf-cached').textContent = cachedPct;
        document.getElementById('cf-threats').textContent = summary.threats.toLocaleString();
        document.getElementById('cf-bytes').textContent = formatBytes(summary.bytes);

        // CF chart
        if (summary.series.length) {
            renderCfChart(summary.series);
        }

        // CF events table
        renderCfEvents(events);
    }

    function renderCfChart(series) {
        const data = [
            series.map(s => s.ts),
            series.map(s => s.requests),
            series.map(s => s.threats),
        ];

        const opts = {
            width: document.getElementById('chart-cf').offsetWidth - 32,
            height: 200,
            series: [
                {},
                { label: 'Requests', stroke: '#7ba2d9', width: 2 },
                { label: 'Threats', stroke: '#d97757', width: 2 },
            ],
            axes: [
                {},
                { scale: 'count' },
            ],
            scales: {
                x: { time: true },
                count: {},
            },
        };

        if (cfChart) {
            cfChart.setData(data);
        } else {
            cfChart = new uPlot(opts, data, document.getElementById('chart-cf'));
        }
    }

    function renderCfEvents(events) {
        const tbody = document.querySelector('#cf-events tbody');
        if (!events.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="muted">No events</td></tr>';
            return;
        }

        tbody.innerHTML = events.map(e => `
            <tr>
                <td>${new Date(e.ts * 1000).toLocaleString()}</td>
                <td>${e.action}</td>
                <td>${e.source}</td>
                <td>${e.country || '—'}</td>
                <td><code>${e.client_ip}</code></td>
                <td><code>${e.uri}</code></td>
            </tr>
        `).join('');
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
        return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' GB';
    }

    // ─── Initial load ───────────────────────────────────────────────

    loadData();
})();
