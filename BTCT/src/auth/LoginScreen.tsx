import { useState } from 'react';
import { useAuthStore } from './auth-store';
import { BrandLockup } from '@/components/ui/Brand';
import { Input, FieldLabel } from '@/components/ui/Field';
import { Button } from '@/components/ui/Button';
import { Banner } from '@/components/ui/Banner';

/**
 * Sign-in screen shown when no user is authenticated. Self-service signup
 * is disabled: only an administrator can create accounts via the in-app
 * admin panel. The default admin accounts are created by the server on boot
 * when missing (see server/index.mjs ensureSeedAccounts).
 */
export function LoginScreen() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const login = useAuthStore((s) => s.login);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim()) {
      setError('username is required');
      return;
    }
    if (!password) {
      setError('password is required');
      return;
    }
    setBusy(true);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'something went wrong');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-viewport w-viewport items-center justify-center overflow-y-auto bg-background p-4 text-foreground">
      <div className="op-login">
      <section className="op-login-intro">
        <span className="op-eyebrow">Operations workspace</span>
        <h1>From the first foothold<br />to the final report.</h1>
        <p>A shared workspace for the evidence, connections, and decisions behind every engagement.</p>
        <div className="op-login-capabilities"><span>Collaborative notes</span><span>Attack narratives</span><span>Reporting</span></div>
      </section>
      <form onSubmit={submit} className="pane-card w-full p-6" aria-labelledby="login-title">
        <BrandLockup className="mb-6" />
        <h2 id="login-title" className="text-sm font-semibold">Been There, Conquered That</h2>
        <p className="mb-5 mt-0.5 text-xs text-muted-foreground">Sign in to your workspace</p>

        <FieldLabel htmlFor="login-user">Username</FieldLabel>
        <Input
          id="login-user"
          autoFocus
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="mb-3 h-8 px-2.5 text-ui"
        />
        <FieldLabel htmlFor="login-pass">Password</FieldLabel>
        <Input
          id="login-pass"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mb-4 h-8 px-2.5 text-ui"
        />

        {error && <Banner tone="red" className="mb-3">{error}</Banner>}

        <Button type="submit" variant="primary" disabled={busy} className="h-8 w-full text-ui">
          {busy ? 'Working…' : 'Log in'}
        </Button>

        <p className="mt-4 text-center text-meta text-muted-foreground">
          Accounts are created by an administrator from inside the app.
        </p>
      </form>
      </div>
    </div>
  );
}
