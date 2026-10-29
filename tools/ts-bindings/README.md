# ts-bindings

Prints the TypeScript declarations of every `tokenator-core` DTO
(`tokenator_core::ts::bindings()`, feature `ts`) as one module on stdout.
It does no file I/O of its own. In `app/`:

```sh
pnpm gen:types    # writes src/lib/engine/types/index.ts
pnpm check:types  # fails if the committed file is out of date
```
