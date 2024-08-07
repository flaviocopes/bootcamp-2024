import {
  addInvite,
  getInvitesForTeam,
  getMembersOfTeam,
  getOwnerOfTeam,
  getTeam,
  addActivity,
} from '@src/data/pocketbase'

import type { APIRoute } from 'astro'

export const POST: APIRoute = async ({ params, request, locals }) => {
  const formData = await request.formData()
  const email = formData.get('email') as string

  const team_id = params.team_id!

  const team = await getTeam(locals.pb, team_id)
  const invites = await getInvitesForTeam(locals.pb, team_id)
  const members = (await getMembersOfTeam(locals.pb, team_id)) || []
  const owner = await getOwnerOfTeam(locals.pb, team)

  if (
    owner.email === email ||
    invites.filter((invite) => invite.email === email).length > 0 ||
    members.filter((member) => member.email === email).length > 0
  ) {
    return new Response(
      'Email belongs to someone already invited or already part of team',
      {
        status: 409,
        statusText: 'Conflict',
        headers: {},
      }
    )
  }

  await addInvite(locals.pb, team_id, email)

  await addActivity({
    pb: locals.pb,
    team: team.id,
    project: '',
    text: `Invite to "${team.name}" created for ${email}`,
    type: 'invite_created',
  })

  return new Response(null, {
    status: 204,
    statusText: 'No Content',
    headers: {
      'HX-Redirect': `/app/team/${params.team_id}/settings`,
    },
  })
}
