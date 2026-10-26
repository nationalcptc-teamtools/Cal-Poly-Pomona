import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import './index.css';
import './themes/operations.css';
import { applyUiTheme } from './themes/registry';
import { restoreUiZoom } from './lib/ui-zoom';
import { installGlobalErrorLogging } from './lib/global-errors';
import { prepareClientCaches, watchRestoreEpoch } from './realtime/restore-epoch';

// Log-only hooks for uncaught errors; installed first so boot failures show.
installGlobalErrorLogging();
// index.html already carries the attribute; stamping it here too keeps a
// cached or hand-edited html from painting the unstyled base.
applyUiTheme();
// Before the first paint, so a zoomed-in device never flashes at 100%.
restoreUiZoom();

// After a server restore, drop the IndexedDB caches before any Yjs doc opens
// (src/realtime/restore-epoch.ts). Resolves at once offline.
void prepareClientCaches().finally(() => {
  watchRestoreEpoch();
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
});
