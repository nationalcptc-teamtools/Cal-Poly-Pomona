export function createSerial(): <T>(job: () => Promise<T>) => Promise<T>;
