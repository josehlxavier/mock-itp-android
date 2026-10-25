export class AppError extends Error {
  constructor(readonly code: string, readonly status = 400) { super(code); }
}
export function ensure(value: unknown, code: string, status = 400): asserts value {
  if (!value) throw new AppError(code, status);
}
