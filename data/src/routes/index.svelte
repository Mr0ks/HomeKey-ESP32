<script lang="ts">
    import { onMount } from "svelte";
    import HKInfo from '$lib/components/HKInfo.svelte';
    import { route } from 'sv-router/generated';
    let entries = $state<{ slot: number; siteHash: string; discoverable: boolean }[]>([]);
    let loading = $state(true);
    let error = $state('');
    async function refresh() {
        loading = true;
        error = '';
        try {
            const result = await fetch('/config?type=passkeys', { cache: 'no-store' }).then(r => r.json());
            if (!result.success) throw new Error(result.error);
            entries = result.data;
        } catch (e) {
            error = e instanceof Error ? e.message : 'Unable to list passkeys.';
        } finally {
            loading = false;
        }
    }
    onMount(() => { void refresh(); });
</script>

<section class="mx-auto max-w-4xl py-8">
    <h1 class="text-3xl font-bold">Passkey security key</h1>
    <p class="mt-2 text-base-content/70">Connect your ESP32 by USB and select Security key when a website asks where to save or use a passkey.</p>
    <div class="mt-6 grid gap-4 md:grid-cols-2">
        <article class="rounded-xl border border-base-300 bg-base-200 p-5">
            <h2 class="font-semibold">Security-key PIN</h2>
            <p class="mt-2 text-sm">In Windows, go to Accounts, Sign-in options, then Security Key and Manage. This PIN is separate from your dashboard password.</p>
        </article>
        <article class="rounded-xl border border-base-300 bg-base-200 p-5">
            <h2 class="font-semibold">Apple Home Key approval</h2>
            <p class="mt-2 text-sm">Enter your security-key PIN when prompted, then tap your iPhone on the NFC reader when Windows asks you to touch the key.</p>
        </article>
    </div>
    <div class="mt-8">
        <div class="flex items-center justify-between gap-4">
            <h2 class="text-xl font-semibold">Stored passkeys</h2>
            <button class="btn btn-sm" onclick={refresh} disabled={loading}>Refresh</button>
        </div>
        {#if loading}
            <p class="mt-2">Loading passkeys...</p>
        {:else if error}
            <p class="mt-2 text-error" role="alert">{error}</p>
        {:else if entries.length === 0}
            <p class="mt-2">No passkeys stored.</p>
        {:else}
            <p class="mt-2 text-sm">The device stores a site hash for each passkey.</p>
            <ul class="mt-3 divide-y divide-base-300">
                {#each entries as entry (entry.slot)}
                    <li class="py-3">
                        <p class="font-semibold">Passkey {entry.slot} · {entry.discoverable ? 'Discoverable' : 'Account-selected'}</p>
                        <p class="break-all font-mono text-xs">{entry.siteHash}</p>
                    </li>
                {/each}
            </ul>
        {/if}
        <a class="link mt-4 inline-block" href="/logs">View device logs</a>
    </div>
</section>

<HKInfo hkInfo={route.meta.homeData?.hkInfo} error={route.meta.homeData?.error} />
