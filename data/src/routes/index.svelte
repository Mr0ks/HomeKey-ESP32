<script>
    import HKInfo from '$lib/components/HKInfo.svelte';
    import { route } from 'sv-router/generated';
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
</section>

<HKInfo hkInfo={route.meta.homeData?.hkInfo} error={route.meta.homeData?.error} />
