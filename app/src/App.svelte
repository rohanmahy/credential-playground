<script lang="ts">
  import AppShell from './lib/components/AppShell.svelte';
  import { setAppContext, type AppContext } from './lib/context';

  let { ctx }: { ctx: AppContext } = $props();
  // The context is fixed for the app's lifetime.
  // svelte-ignore state_referenced_locally
  setAppContext(ctx);
</script>

<AppShell />
