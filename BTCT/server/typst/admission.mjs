// How many exports may be in flight at once, counting the one running.
//
// The queue in serial.mjs runs jobs one at a time but accepts every job it is
// given, so one account could line up hundreds of slow compiles, each holding
// a socket and a staged directory's worth of work. This is the bound in front
// of it: over the limit, the caller gets a 429 straight away instead of a
// connection that sits there for minutes.
//
// Pure: no timers, no IO, so src/test covers it through the .d.mts beside
// this file.
export function createAdmission(limit) {
  let pending = 0;
  return {
    /** True when a slot was taken. Every true must be paired with a leave(). */
    enter() {
      if (pending >= limit) return false;
      pending += 1;
      return true;
    },
    /** Called from a finally, so it runs on success, failure and cancellation alike. */
    leave() {
      pending = Math.max(0, pending - 1);
    },
    pending: () => pending,
  };
}
