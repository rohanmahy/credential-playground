/** Thrown by scaffold stubs that the implementation phase fills in. */
export class NotImplemented extends Error {
  constructor(what: string) {
    super(`not implemented: ${what}`);
    this.name = 'NotImplemented';
  }
}

export function notImplemented(what: string): never {
  throw new NotImplemented(what);
}
