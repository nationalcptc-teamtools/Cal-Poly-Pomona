// The import is the only code in the branch that deliberately destroys
// report content, and the report has no version history to recover it from.
// The three-state `typstSource` (a string, a known-absent null, an unknown
// undefined) crossed with the two import modes is the whole decision, so it
// is a pure function with a test per combination.
import { describe, it, expect } from 'vitest';
import { reportImportAction } from '@/export/workspace-zip';

describe('reportImportAction', () => {
  it('writes the archived report in both import modes', () => {
    expect(reportImportAction('= Report', 'replace', true)).toBe('write');
    expect(reportImportAction('= Report', 'new', false)).toBe('write');
  });

  it('clears an existing report only when the archive knows there was none', () => {
    // report.typ absent AND the manifest counted 0: the exported workspace
    // really had no report, so a faithful replace removes the one here.
    expect(reportImportAction(null, 'replace', true)).toBe('clear');
  });

  it('leaves a report alone when the archive cannot say either way', () => {
    // An older or manifest-less archive never recorded whether a report
    // existed, so a replace must not destroy one.
    expect(reportImportAction(undefined, 'replace', true)).toBe('none');
  });

  it('never clears when the import lands in a fresh workspace', () => {
    // Import-as-new writes into a remapped workspace id, which by definition
    // has no report of its own to clear.
    expect(reportImportAction(null, 'new', false)).toBe('none');
    expect(reportImportAction(undefined, 'new', false)).toBe('none');
  });

  it('never clears a workspace that does not exist yet', () => {
    expect(reportImportAction(null, 'replace', false)).toBe('none');
  });

  it('treats an empty report.typ as nothing to write, and leaves any existing one', () => {
    // Matches the behaviour this replaced: the old `if (data.typstSource)`
    // was falsy for '', and '' is not `null`, so neither branch ran.
    expect(reportImportAction('', 'replace', true)).toBe('none');
    expect(reportImportAction('', 'new', false)).toBe('none');
  });
});
