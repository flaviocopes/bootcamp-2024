import Stripe from 'stripe'

export function initStripe() {
  return new Stripe(
    import.meta.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY,
    {
      typescript: true,
    }
  )
}
