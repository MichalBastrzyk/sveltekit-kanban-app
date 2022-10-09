import { invalid, redirect } from '@sveltejs/kit';
import type { Action, Actions, PageServerLoad } from './$types';
import bcrypt from 'bcrypt';

import { db } from '$lib/database';

export const load: PageServerLoad = async ({ locals }) => {
	if (locals.user) {
		throw redirect(302, '/');
	}
};

const login: Action = async ({ request, cookies }) => {
	const data = await request.formData();
	const username = data.get('username');
	const password = data.get('password');

	if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
		return invalid(400, { invalid: true });
	}

	const user = await db.user.findUnique({ where: { username } });

	if (!user) {
		return invalid(400, { invalid: true });
	}

	const userPassword = bcrypt.compare(password, user.passwordHash);

	if (!userPassword) {
		return invalid(400, { invalid: true });
	}

	const authenticatedUser = await db.user.update({
		where: { username: user.username },
		data: { userAuthToken: crypto.randomUUID() }
	});

	cookies.set('session', authenticatedUser.userAuthToken, {
		path: '/',
		httpOnly: true,
		sameSite: true,
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 30
	});

	throw redirect(302, '/');
};

export const actions: Actions = { login };
