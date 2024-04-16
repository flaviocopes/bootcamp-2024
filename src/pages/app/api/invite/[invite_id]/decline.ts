import { deleteInvite } from '@src/data/pocketbase'

import type { APIRoute } from 'astro'

export const POST: APIRoute = async ({ params }) => {
  await deleteInvite(params.invite_id!)

  return new Response(null, {
    status: 204,
    statusText: 'No Content',
    headers: {
      'HX-Redirect': '/app/dashboard',
    },
  })
}
