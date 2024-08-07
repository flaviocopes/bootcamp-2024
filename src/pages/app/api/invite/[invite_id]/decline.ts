import {
  deleteInvite,
  addActivity,
  getInvite,
  getTeam,
} from '@src/data/pocketbase'

import { getUserUsername } from '@lib/auth'

import type { APIRoute } from 'astro'

export const POST: APIRoute = async ({ params, request, locals }) => {
  const invite = await getInvite(locals.pb, params.invite_id!)
  const team = await getTeam(locals.pb, invite.team)

  await deleteInvite(locals.pb, params.invite_id!)

  await addActivity({
    pb: locals.pb,
    team: team.id,
    project: '',
    text: `Team ${team.name} invite declined by @${await getUserUsername(
      locals.pb,
      request
    )}`,
    type: 'invite_declined',
  })

  return new Response(null, {
    status: 204,
    statusText: 'No Content',
    headers: {
      'HX-Redirect': '/app/dashboard',
    },
  })
}
