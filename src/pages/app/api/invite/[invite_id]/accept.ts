import {
  addMember,
  deleteInvite,
  getInvite,
  addActivity,
  getTeam,
} from '@src/data/pocketbase'

import { getCurrentUserId, getUserUsername } from '@lib/auth'

import type { APIRoute } from 'astro'

export const POST: APIRoute = async ({ params, request }) => {
  const invite = await getInvite(params.invite_id!)
  const team = await getTeam(invite.team)

  if (invite) {
    await addMember(invite.team, getCurrentUserId())
    await deleteInvite(params.invite_id!)
  }

  await addActivity({
    team: team.id,
    project: '',
    text: `Team ${team.name} invite accepted by @${await getUserUsername(
      request
    )}`,
    type: 'invite_accepted',
  })

  return new Response(null, {
    status: 204,
    statusText: 'No Content',
    headers: {
      'HX-Redirect': invite ? `/app/team/${invite.team}` : '/app/dashboard',
    },
  })
}
