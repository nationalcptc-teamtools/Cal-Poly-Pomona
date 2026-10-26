import { useEffect, useState } from 'react';
import { getPageYContext } from './yjs-providers';

/**
 * True while the page's provider is synced with the server. The version
 * history disables Restore until then (see `restorePageVersion`).
 */
export function usePageServerSynced(pageId: string): boolean {
  const [synced, setSynced] = useState(() => getPageYContext(pageId).provider.synced);
  useEffect(() => {
    const provider = getPageYContext(pageId).provider;
    const onSync = (s: boolean) => setSynced(s);
    setSynced(provider.synced);
    provider.on('sync', onSync);
    return () => provider.off('sync', onSync);
  }, [pageId]);
  return synced;
}
