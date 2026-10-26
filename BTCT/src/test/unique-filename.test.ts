import { describe, expect, it } from 'vitest';
import { pickUniqueFilename, takenFilenames } from '@/db/asset-repo';

// CLI-14: one set of taken names per call, so a paste named image.png at 500
// existing assets is a set walk, not 500 workspace scans.
describe('pickUniqueFilename', () => {
  it('keeps a free name and suffixes a taken one, case-insensitively', () => {
    const taken = takenFilenames([{ id: 'a', filename: 'Image.PNG' }, { id: 'b', filename: 'image-2.png' }]);
    expect(pickUniqueFilename(taken, 'shot.png')).toBe('shot.png');
    expect(pickUniqueFilename(taken, 'image.png')).toBe('image-3.png');
  });

  it('handles names without an extension and ignores the excepted id', () => {
    const taken = takenFilenames([{ id: 'a', filename: 'notes' }, { id: 'b', filename: 'x.png' }], 'b');
    expect(pickUniqueFilename(taken, 'notes')).toBe('notes-2');
    expect(pickUniqueFilename(taken, 'x.png')).toBe('x.png');
  });

  it('finds the next free suffix among 500 pasted images quickly', () => {
    const assets = [{ id: '0', filename: 'image.png' }];
    for (let n = 2; n <= 500; n++) assets.push({ id: String(n), filename: `image-${n}.png` });
    const t0 = performance.now();
    const name = pickUniqueFilename(takenFilenames(assets), 'image.png');
    const ms = performance.now() - t0;
    expect(name).toBe('image-501.png');
    expect(ms).toBeLessThan(50);
  });
});
