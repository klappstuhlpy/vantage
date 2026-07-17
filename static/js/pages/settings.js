/* Settings page — save the operational overlay over config.json.
 *
 * Each field maps to one override key. An empty field means "no override, use
 * the config.json default", sent as null so the server clears the row. The save
 * is sudo-gated server-side; core/api.js handles the reauth prompt and retry, so
 * nothing here has to know about it.
 */

import { post } from '../core/api.js';
import { toastOk, withLoading } from '../core/ui.js';

const form = document.getElementById('settings-form');
const saveBtn = document.getElementById('settings-save');

/** An input's value as an integer, or null when blank (= use the default). */
function intOrNull(id) {
  const v = document.getElementById(id).value.trim();
  if (v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    audit_retention_days: intOrNull('audit_retention_days'),
    update_check_interval_hours: intOrNull('update_check_interval_hours'),
    backup_interval_hours: intOrNull('backup_interval_hours'),
    backup_keep: intOrNull('backup_keep'),
  };
  try {
    await withLoading(saveBtn, () => post('/settings', body), { errorTitle: "Couldn't save settings" });
    toastOk('Settings saved', 'Applied on the next scheduled run.');
  } catch {
    /* withLoading already surfaced the error toast */
  }
});
