import { describe, it, expect } from 'vitest';
import { resolveFeatures, DEFAULT_FEATURES } from '@/lib/features';

describe('resolveFeatures', () => {
  it('is all-off by default', () => {
    expect(DEFAULT_FEATURES).toEqual({ typst: false });
  });
  it('reads features.typst === true', () => {
    expect(resolveFeatures({ features: { typst: true } })).toEqual({ typst: true });
  });
  it('treats anything but literal true as off', () => {
    for (const bad of [undefined, null, {}, { features: null }, { features: { typst: 'true' } }, { features: { typst: 1 } }, 'x']) {
      expect(resolveFeatures(bad)).toEqual({ typst: false });
    }
  });
});
