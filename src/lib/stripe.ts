import Stripe from 'stripe'

export function initStripe() {
  return new Stripe(
    import.meta.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY,
    {
      typescript: true,
    }
  )
}

export async function cancelSubscription(subscription_id: string) {
  const stripe = initStripe()

  try {
    await stripe.subscriptions.cancel(subscription_id)
  } catch (error) {
    console.error('Error during cancellation: ', error)
    throw error
  }
}

export async function searchSubscriptionsByTeamId(
  team_id: string,
  return_url?: string
) {
  const stripe = initStripe()
  const search = await stripe.subscriptions.search({
    expand: ['data.customer'],
    query: `metadata["team_id"]:"${encodeURI(team_id)}" AND status:'active'`,
  })

  const res = await Promise.all(
    search.data.map(async subscription => {
      const customer = subscription.customer
      if (typeof customer === 'string') {
        throw new Error('data.customer was not expanded in search')
      }
      const portal_url = return_url
        ? (
            await stripe.billingPortal.sessions.create({
              customer: customer.id,
              return_url: return_url,
            })
          ).url
        : undefined
      return {
        id: subscription.id,
        active: subscription.status === 'active',
        email: 'email' in customer && customer.email,
        portal_url,
      }
    })
  )
  return res
}
