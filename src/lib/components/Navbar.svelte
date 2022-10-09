<script lang="ts">
	import { page } from '$app/stores';
</script>

<nav class="fixed flex w-screen items-center justify-between p-4 mb-4 bg-gray-50">
	<a href="/">Home</a>
	<a href="/kanban" class="flex gap-2"> Kanban view</a>

	{#if !$page.data.user}
		<ul class="flex gap-4">
			<li>
				<a href="/user/login">Sign in</a>
			</li>
			<li>
				<a href="/user/register">Sign up</a>
			</li>
		</ul>
	{/if}

	{#if $page.data.user}
		<div class="flex justify-center items-center">
			<h1 class="text-xl font-bold">Hello {$page.data.user.name}</h1>
			<a href="/user" class="flex gap-4 justify-center items-center">
				<img src="images/user.jpg" alt="" class="w-12 h-12 rounded-full object-cover" />
				Your Profile
			</a>
			<form action="/user/logout" method="POST">
				<button
					type="submit"
					class="p-1 rounded-md border-2 shadow-md border-red-500 bg-red-300 text-red-600 active:bg-red-400"
				>
					Logout
				</button>
			</form>
		</div>
	{/if}
</nav>
