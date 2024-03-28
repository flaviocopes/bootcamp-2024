import { initStripe } from '@lib/stripe'

import type { APIRoute } from 'astro'

export const POST: APIRoute = async ({ params, request }) => {
  const team_id = params.team_id

  const team_page_url = new URL(
    '/app/api/stripe/callback/success/' + team_id,
    request.url
  ).toString()

  const stripe = initStripe()

  const session = await stripe.checkout.sessions.create({
    //@ts-expect-error
    client_reference_id: team_id,
    line_items: [
      {
        price: import.meta.env.STRIPE_PRICE_ID || process.env.STRIPE_PRICE_ID,
        quantity: 1,
      },
    ],
    subscription_data: {
      metadata: {
        what: 'subscription_data',
        team_id,
        team_page_url,
      },
    },
    metadata: {
      what: 'checkout_session',
      team_id,
      team_page_url,
    },
    mode: 'subscription',
    success_url: team_page_url + '?refresh=true',
    cancel_url: team_page_url,
  })

  const { url } = session

  if (!url) {
    throw new Error('An unexpected error happened')
  }

  const response = new Response(null, { status: 200 })
  response.headers.set('HX-Redirect', url)

  return response
}
