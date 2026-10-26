import { type ClassValue, clsx } from 'clsx';
import { extendTailwindMerge } from 'tailwind-merge';

/**
 * tailwind-merge told about the theme's named type scale (tokens.css).
 * Without this it reads `text-micro` as a text colour and `cn('text-micro',
 * 'text-muted-foreground')` silently drops the size.
 */
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      'font-size': [{ text: ['micro', 'caption', 'meta', 'ui'] }],
      shadow: [{ shadow: ['pane'] }],
    },
  },
});

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
