import { defineMiddleware } from 'astro/middleware'
import { isLoggedIn, isUserVerified } from '@lib/auth'

export const onRequest = defineMiddleware(async (context, next) => {
  //special cases for stripe workflow
  if (
    context.url.pathname === '/app/api/stripe/webhook' ||
    context.url.pathname.startsWith('/app/api/stripe/callback/success/')
  ) {
    return next()
  } else {
    if (!(await isLoggedIn(context.request))) {
      if (context.url.pathname.startsWith('/app/api')) {
        return new Response('Unauthorized', {
          status: 401,
        })
      }

      if (context.url.pathname.startsWith('/app')) {
        return context.redirect('/login')
      }
    }

    if (await isLoggedIn(context.request)) {
      const verified = await isUserVerified()
      if (!verified) {
        if (context.url.pathname.startsWith('/app')) {
          return context.redirect('/verify')
        }
      } else {
        if (context.url.pathname === '/verify') {
          return context.redirect('/app/dashboard')
        }
      }
    }
  }

  return next()
})
