// Log viewer — fetches /logs/data and renders filtered lines.
// Extracted from the page template so a strict CSP with no inline script holds.
(function () {
    const view = document.getElementById('log-view');
    const fileSel = document.getElementById('log-file');
    const levelSel = document.getElementById('log-level');
    const qInput = document.getElementById('log-q');
    const limitSel = document.getElementById('log-limit');
    const auto = document.getElementById('log-auto');
    let timer = null;

    function esc(s) {
        return (s || '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    }

    async function load() {
        const params = new URLSearchParams({
            file: fileSel.value,
            level: levelSel.value,
            q: qInput.value,
            limit: limitSel.value,
        });
        try {
            const r = await fetch(`/logs/data?${params}`);
            const data = await r.json();
            if (!data.lines || !data.lines.length) {
                view.innerHTML = '<div class="log-empty">No matching log lines.</div>';
                return;
            }
            view.innerHTML = data.lines.map(l => {
                const ts = esc((l.ts || '').replace('T', ' ').replace(/\.\d+Z?$/, ''));
                const lvl = esc(l.level || '');
                const msg = esc(l.message || l.raw || '');
                const tgt = l.target ? `<span class="log-ts">${esc(l.target)}</span>` : '';
                return `<div class="log-row"><span class="log-ts">${ts}</span>` +
                    `<span class="log-lvl ${lvl}">${lvl}</span>` +
                    `<span class="log-msg">${msg} ${tgt}</span></div>`;
            }).join('');
            view.scrollTop = view.scrollHeight;
        } catch (_) {
            view.innerHTML = '<div class="log-empty">Failed to load logs.</div>';
        }
    }

    document.getElementById('log-refresh').addEventListener('click', load);
    [fileSel, levelSel, limitSel].forEach(el => el.addEventListener('change', load));
    let debounce;
    qInput.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(load, 250); });
    auto.addEventListener('change', () => {
        if (auto.checked) timer = setInterval(load, 5000);
        else clearInterval(timer);
    });
    load();
})();
