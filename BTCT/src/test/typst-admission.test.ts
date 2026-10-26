import { describe, it, expect } from 'vitest';
import { createAdmission } from '../../server/typst/admission.mjs';

// The export queue runs one job at a time and never dropped anything, so a
// single account could line up hundreds of slow compiles, each holding a
// socket open. Admission is the bound in front of the queue.

describe('createAdmission', () => {
  it('admits up to the limit and refuses the rest', () => {
    const gate = createAdmission(2);
    expect(gate.enter()).toBe(true);
    expect(gate.enter()).toBe(true);
    expect(gate.enter()).toBe(false);
    expect(gate.pending()).toBe(2);
  });

  it('frees a slot on leave, whatever the job did', () => {
    const gate = createAdmission(2);
    gate.enter();
    gate.enter();
    expect(gate.enter()).toBe(false);
    gate.leave(); // the job succeeded
    expect(gate.enter()).toBe(true);
    gate.leave(); // the job threw
    gate.leave(); // the job was cancelled
    // Three enters, three leaves, whatever each job did.
    expect(gate.pending()).toBe(0);
  });

  it('never counts below zero, however often leave is called', () => {
    const gate = createAdmission(1);
    gate.leave();
    gate.leave();
    expect(gate.pending()).toBe(0);
    expect(gate.enter()).toBe(true);
    expect(gate.enter()).toBe(false);
  });

  it('keeps separate gates apart', () => {
    const a = createAdmission(1);
    const b = createAdmission(1);
    expect(a.enter()).toBe(true);
    expect(b.enter()).toBe(true);
    expect(a.enter()).toBe(false);
  });

  it('refuses everything at a limit of zero', () => {
    expect(createAdmission(0).enter()).toBe(false);
  });
});
