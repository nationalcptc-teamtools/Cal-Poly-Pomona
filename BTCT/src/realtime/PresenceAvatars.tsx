/**
 * Floating "active users" window: the entry point for live-following a
 * teammate. Toggled by the `openFollowPanel` keybind (default Ctrl/⌘+Shift+U)
 * or the command palette, via the `followPanelOpen` store flag.
 *
 * Lists online teammates and what each is looking at, with a Follow / Stop
 * toggle. When you follow while your layout is split for the first time, a
 * one-off prompt asks whether the followed view should slot into one of your
 * panes or take over the screen; the choice is remembered in your profile.
 */
import { useEffect, useState } from 'react';
import { Button, IconButton, ToggleChip } from '@/components/ui/Button';
import { X, Users, Eye, EyeOff } from 'lucide-react';
import { useAppStore } from '@/stores';
import { useAuthStore, type AuthUser } from '@/auth/auth-store';
import { resolvePrefs } from '@/lib/editor-prefs';
import { isSplit } from '@/lib/pane-layout';
import type { TabKind } from '@/types';
import { usePresenceRoster, type PeerPresence } from './presence';

const KIND_LABEL: Record<TabKind, string> = {
  page: 'Page',
  nmap: 'Nmap',
  'nmap-machine': 'Host',
  cmdlog: 'Command Log',
  history: 'History',
  assets: 'Assets',
  shortcuts: 'Shortcuts',
  typst: 'Report',
  'web-scan': 'Web Scans',
};

function whereLabel(peer: PeerPresence): string {
  const f = peer.focus;
  if (!f) return 'Idle';
  const kind = KIND_LABEL[f.kind] ?? f.kind;
  return f.title ? `${kind} · ${f.title}` : kind;
}

export function PresenceAvatars() {
  const open = useAppStore((s) => s.followPanelOpen);
  const setOpen = useAppStore((s) => s.setFollowPanelOpen);
  const followingUserId = useAppStore((s) => s.followingUserId);
  const setFollowingUserId = useAppStore((s) => s.setFollowingUserId);
  const user = useAuthStore((s) => s.user) as AuthUser;
  const updateProfile = useAuthStore((s) => s.updateProfile);
  const peers = usePresenceRoster();

  // Which peer id is awaiting a pane-placement choice (first split-follow).
  const [promptFor, setPromptFor] = useState<number | null>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !e.defaultPrevented) setOpen(false); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, setOpen]);

  if (!open) return null;

  const handleFollow = (peer: PeerPresence) => {
    if (followingUserId === peer.user.id) {
      setFollowingUserId(null);
      return;
    }
    const placement = resolvePrefs(user).follow.panePlacement;
    if (isSplit(useAppStore.getState().paneLayout) && placement === null) {
      setPromptFor(peer.user.id);
      return;
    }
    setFollowingUserId(peer.user.id);
  };

  const choosePlacement = async (choice: 'split' | 'takeover', peerId: number) => {
    const resolved = resolvePrefs(user);
    try {
      await updateProfile({
        prefs: {
          ...resolved,
          follow: { ...resolved.follow, panePlacement: choice },
        },
      });
    } catch {
      /* non-fatal: still follow this session even if the pref didn't persist */
    }
    setPromptFor(null);
    setFollowingUserId(peerId);
  };

  // A non-modal panel (you keep working while following), so not a Dialog;
  // it still names itself and closes on Escape.
  return (
    <div
      role="dialog"
      aria-labelledby="follow-panel-title"
      className="fixed right-3 top-12 z-50 w-[min(18rem,calc(100*var(--vw)-24px))] overflow-hidden rounded-lg bg-popover text-popover-foreground shadow-pane"
    >
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <Users size={14} className="text-primary" />
          <h2 id="follow-panel-title" className="text-caption font-bold uppercase tracking-widest text-muted-foreground">Active Users</h2>
        </div>
        <IconButton label="Close" onClick={() => setOpen(false)}>
          <X size={14} />
        </IconButton>
      </div>

      <div className="max-h-[calc(60*var(--vh))] overflow-y-auto p-2">
        {peers.length === 0 ? (
          <div className="px-2 py-6 text-center text-meta text-muted-foreground">
            No other users online.
          </div>
        ) : (
          <ul className="flex flex-col gap-1">
            {peers.map((peer) => {
              const isFollowing = followingUserId === peer.user.id;
              const isPrompting = promptFor === peer.user.id;
              return (
                <li
                  key={peer.user.id}
                  className="rounded px-2 py-1.5 hover:bg-accent"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="h-2.5 w-2.5 flex-shrink-0 rounded-full"
                      style={{ backgroundColor: peer.user.color }}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-xs font-medium">{peer.user.name}</div>
                      <div className="truncate text-caption text-muted-foreground">
                        {whereLabel(peer)}
                      </div>
                    </div>
                    <ToggleChip
                      pressed={isFollowing}
                      onClick={() => handleFollow(peer)}
                      disabled={!peer.focus && !isFollowing}
                      title={isFollowing ? 'Stop following' : 'Follow'}
                      aria-label={isFollowing ? `Stop following ${peer.user.name}` : `Follow ${peer.user.name}`}
                      className="py-1 font-semibold uppercase tracking-wider"
                    >
                      {isFollowing ? <EyeOff size={11} /> : <Eye size={11} />}
                      {isFollowing ? 'Stop' : 'Follow'}
                    </ToggleChip>
                  </div>

                  {isPrompting && (
                    <div className="mt-2 rounded-md border border-border bg-background p-2">
                      <p className="mb-1.5 text-caption text-muted-foreground">
                        You have split panes. Where should followed views go?
                      </p>
                      <div className="flex gap-1.5">
                        <Button variant="outline" size="sm" className="flex-1 text-caption" onClick={() => void choosePlacement('split', peer.user.id)}>
                          Into a pane
                        </Button>
                        <Button variant="outline" size="sm" className="flex-1 text-caption" onClick={() => void choosePlacement('takeover', peer.user.id)}>
                          Take over
                        </Button>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="border-t border-border px-3 py-2 text-caption text-muted-foreground">
        Set per-teammate precision in Profile → Following.
      </div>
    </div>
  );
}
