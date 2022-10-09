<script lang="ts">
	import type { ActionData } from './$types';

	export let form: ActionData;
</script>

<h1 class="text-4xl">Register</h1>

<form action="?/register" method="POST" class="flex flex-col gap-4 justify-center items-center">
	<div class={`flex flex-col ${form?.taken || form?.invalid ? 'text-red-700' : null}`}>
		<label for="username">Username*</label>
		<input type="text" name="username" id="username" class="p-2" />
	</div>

	<div class={`flex flex-col ${form?.taken || form?.invalid ? 'text-red-700' : null}`}>
		<label for="password">Password*</label>
		<input type="password" name="password" id="password" class="p-2" />
	</div>

	{#if form?.taken}
		<p class="test-md p-4 bg-red-400 text-white rounded-md border-2 border-red-500">
			Username is taken
		</p>
	{/if}

	{#if form?.invalid}
		<p>Input is invalid</p>
	{/if}

	<button type="submit" class="px-4 py-2 rounded-md bg-cyan-600 w-40">Register</button>
</form>
