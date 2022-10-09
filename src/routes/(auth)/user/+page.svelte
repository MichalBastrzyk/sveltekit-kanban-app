<script lang="ts">
	import { page } from '$app/stores';
</script>

<div class="flex items-center p-2 gap-2">
	<img src="images/user.jpg" alt="" class="rounded-full w-32 h-32 object-cover" />
	<h1 class="text-4xl font-bold">How are u today {$page.data.user.name}</h1>
</div>

<div>
	<h2 class="text-2xl font-semibold">Account settings</h2>
	<button>Change username</button>
	<button>Change password</button>
</div>
