import { cn } from '@/lib/utils';

/**
 * The horizontal BTCT lockup (brand/BRAND.md): the one-colour mark in the
 * accent and the drawn wordmark in the text colour, both CSS masks over
 * public/logo-mark-mono.svg and public/wordmark.svg so they follow the mode
 * and the admin accent. Proportions follow brand/logo-lockup-horizontal.svg;
 * at the default 40px mark it is just over the 96px minimum lockup width.
 */
export function BrandLockup({ className }: { className?: string }) {
  return (
    <span className={cn('op-lockup', className)} role="img" aria-label="BTCT">
      <span className="op-brand-mark" aria-hidden />
      <span className="op-brand-word" aria-hidden />
    </span>
  );
}
