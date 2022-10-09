<script lang="ts">
	import type { ActionData } from './$types';
	import toast from 'svelte-french-toast';

	export let form: ActionData;

	$: if (form?.invalid) toast.error('Invalid cridentials 😕');
</script>

<h1 class="text-4xl">Login</h1>

<form action="?/login" method="POST" class="flex flex-col gap-4 justify-center items-center">
	<div class={`flex flex-col ${form?.invalid ? 'text-red-700' : null}`}>
		<label for="username">Username*</label>
		<input type="text" name="username" id="username" class="p-2" />
	</div>

	<div class={`flex flex-col ${form?.invalid ? 'text-red-700' : null}`}>
		<label for="password">Password*</label>
		<input type="password" name="password" id="password" class="p-2" />
	</div>

	{#if form?.invalid}
		<p class="test-md p-4 bg-red-400 text-white rounded-md border-2 border-red-500">
			Invalid cridentials
		</p>
	{/if}

	<button type="submit" class="px-4 py-2 rounded-md bg-cyan-600 w-40">Log in</button>
</form>
