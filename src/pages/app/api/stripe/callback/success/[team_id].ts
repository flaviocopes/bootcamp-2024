import type { APIRoute } from 'astro'

export const GET: APIRoute = async context => {
  const team_id = context.params.team_id

  const team_page_url = new URL(
    '/app/team/' + team_id,
    context.request.url
  ).toString()

  return new Response(
    '<html><head><meta http-equiv="refresh" content="0;url=' +
      team_page_url +
      '"></head><body></body></html>',
    {
      headers: {
        'content-type': 'text/html;charset=UTF-8',
      },
      status: 200,
    }
  )
}
