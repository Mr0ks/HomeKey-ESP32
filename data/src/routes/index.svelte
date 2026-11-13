<script lang="ts">
    import { onMount } from "svelte";
    import PairingQR from "$lib/components/PairingQR.svelte";
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
    let pairingDialog: HTMLDialogElement;
    let setupCode = $state('');
    let nfcMessage = $state('');
    let nfcUntil = 0;
    async function startNfcPairing() {
        if (Date.now() < nfcUntil) return;
        nfcUntil = Date.now() + 30_000;
        try {
            const result = await fetch('/pairing/nfc', {
                method: 'POST', headers: { 'X-HomeKey-Pairing': '1' }
            }).then(r => r.json());
            if (!result.success) throw new Error(result.error);
            nfcMessage = 'Open Apple Home, choose Add Accessory, and hold the top of your iPhone near the PN532 within 30 seconds.';
        } catch (e) {
            nfcUntil = 0;
            nfcMessage = e instanceof Error ? e.message : 'Could not start NFC pairing.';
        }
    }
    let pairingError = $state('');
    const dismissalKey = 'apple-home-pairing-dismissed';

    async function openPairing() {
        setupCode = '';
        pairingError = '';
        if (!pairingDialog.open) pairingDialog.showModal();
        try {
            const result = await fetch('/config?type=misc', { cache: 'no-store' }).then(r => r.json());
            if (!result.success || !result.data?.setupCode) {
                throw new Error(result.error || 'No setup code is available.');
            }
            setupCode = result.data.setupCode;
        } catch (e) {
            pairingError = e instanceof Error ? e.message : 'Unable to load the setup code.';
        }
    }

    onMount(() => {
        void refresh();
        const info = route.meta.homeData?.hkInfo;
        if (info && !info.issuers?.some(issuer => issuer.endpoints?.length) &&
            !sessionStorage.getItem(dismissalKey)) {
            void openPairing();
        }
    });
</script>

<dialog bind:this={pairingDialog} class="modal" aria-labelledby="pairing-title"
    onclose={() => sessionStorage.setItem(dismissalKey, '1')}>
    <div class="modal-box">
        <h2 id="pairing-title" class="text-xl font-bold">Add to Apple Home</h2>
        <p class="my-3">On your iPhone, open Home, tap +, and choose Add Accessory. Scan the QR code below. If this dashboard is open on your iPhone, use the setup code under More options.</p>
        {#if pairingError}
            <p role="alert" class="text-error">{pairingError}</p>
        {:else if setupCode}
            <PairingQR {setupCode} />
        {:else}
            <p role="status">Loading setup code...</p>
        {/if}
        <button class="btn btn-primary mt-4" onclick={startNfcPairing}>Start NFC pairing</button>
        {#if nfcMessage}<p class="mt-2" role="status">{nfcMessage}</p>{/if}
        <form method="dialog" class="modal-action"><button class="btn">Close</button></form>
    </div>
</dialog>

<section class="mx-auto max-w-4xl py-8">
    <h1 class="text-3xl font-bold">Passkey security key</h1>
    <p class="mt-2 text-base-content/70">Connect your ESP32 by USB and select Security key when a website asks where to save or use a passkey.</p>
    <button class="btn mt-4" onclick={openPairing}>Add to Apple Home</button>
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
