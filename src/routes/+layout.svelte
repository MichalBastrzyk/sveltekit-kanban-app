<script lang="ts">
	import { Toaster } from 'svelte-french-toast';
	import Navbar from '$lib/components/Navbar.svelte';
	import '../app.css';
</script>

<Toaster />
<Navbar />
<main class="pt-20 px-2 w-full h-full max-w-7xl m-auto bg-slate-200">
	<slot />
</main>
