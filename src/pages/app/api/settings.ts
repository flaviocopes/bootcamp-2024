import {
  getUserUsername,
  getCookie,
  setUserUsername,
  updateOwnUsername,
} from '@lib/auth'

import { addActivity } from '@src/data/pocketbase'

import type { APIRoute } from 'astro'

export const PUT: APIRoute = async ({ request, locals }) => {
  const formData = await request.formData()
  let username = formData.get('username') as string

  username = username.replace(/[^a-zA-Z0-9]/g, '')

  if (username.length < 3) {
    return new Response('Username must be 3 chars or more', {
      status: 400,
    })
  }
  try {
    await updateOwnUsername(locals.pb, username)
  } catch (e) {
    //most probably username already taken
    return new Response('Username already taken', {
      status: 400,
    })
  }

  await addActivity({
    pb: locals.pb,
    team: '',
    project: '',
    text: `Username changed from ${await getUserUsername(
      locals.pb,
      request
    )} to ${username}`,
    type: 'team_delete',
  })

  setUserUsername(locals.pb, username)

  return new Response(null, {
    status: 204,
    headers: {
      statusText: 'No Content',
      'Set-Cookie': getCookie(locals.pb),
      'HX-Redirect': '/app/settings',
    },
  })
}
