import type { UsersResponse, TypedPocketBase } from '@src/data/pocketbase-types'

export const isValidEmail = (email: string) => {
  if (typeof email !== 'string') return false
  if (email.length > 255) return false
  const regex = /^.+@.+$/
  return regex.test(email)
}

export const isValidPassword = (password: string) => {
  if (typeof password !== 'string') return false
  if (password.length > 255) return false
  if (password.length < 4) return false
  return true
}

export function isValidData(email: string, password: string) {
  if (!isValidEmail(email)) {
    return false
  }

  if (!isValidPassword(password)) {
    return false
  }

  return true
}

export async function createUser(
  pb: TypedPocketBase,
  email: string,
  password: string
) {
  return await pb.collection('users').create({
    email: email,
    password: password,
    passwordConfirm: password,
    emailVisibility: true,
  })
}

export async function loginUser(
  pb: TypedPocketBase,
  email: string,
  password: string
) {
  return await pb.collection('users').authWithPassword(email, password)
}

export function setCookieAndRedirectToDashboard(pb: TypedPocketBase) {
  return new Response(null, {
    status: 301,
    headers: {
      Location: '/app/dashboard',
      //set secure false on localhost for Safari compatibility
      'Set-Cookie': pb.authStore.exportToCookie({
        secure: import.meta.env.DEV ? false : true,
      }),
    },
  })
}

export async function isLoggedIn(pb: TypedPocketBase, request: Request) {
  if (!request.headers.get('Cookie')) {
    return false
  }

  pb.authStore.loadFromCookie(request.headers.get('Cookie') || '', 'pb_auth')

  try {
    // get an up-to-date auth store state by veryfing and refreshing the loaded auth model (if any)
    if (pb.authStore.isValid && (await pb.collection('users').authRefresh())) {
      return true
    }
  } catch (_) {
    // clear the auth store on failed refresh
    pb.authStore.clear()
  }

  return false
}

export async function getUserUsername(pb: TypedPocketBase, request: Request) {
  pb.authStore.loadFromCookie(request.headers.get('Cookie') || '', 'pb_auth')
  return pb.authStore.model?.username
}

export async function sendResetPasswordLink(
  pb: TypedPocketBase,
  email: string
) {
  await pb.collection('users').requestPasswordReset(email)
}

export async function getUserObjectFromDb(
  pb: TypedPocketBase,
  user_id: string
) {
  const user: UsersResponse = await pb.collection('users').getOne(user_id)

  return user
}

export function getCurrentUserId(pb: TypedPocketBase) {
  return pb.authStore.model?.id
}

export function getCurrentUserEmail(pb: TypedPocketBase) {
  return pb.authStore.model?.email
}

export async function isUserVerified(pb: TypedPocketBase) {
  //we load from db as user object is not updated immediately if user clicks verify email
  const user = await getUserObjectFromDb(pb, getCurrentUserId(pb))
  return user.verified
}

export async function sendVerificationEmail(
  pb: TypedPocketBase,
  email: string
) {
  await pb.collection('users').requestVerification(email)
}

export async function processTurnstile(cf_turnstile_response: string) {
  const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

  const requestBody = new URLSearchParams({
    secret:
      import.meta.env.TURNSTILE_SITE_SECRET ||
      process.env.TURNSTILE_SITE_SECRET,
    response: cf_turnstile_response,
  })

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: requestBody.toString(),
  })

  const data = await response.json()

  return data.success
}

export function setUserUsername(pb: TypedPocketBase, username: string) {
  pb.authStore.model!.username = username
}

export async function updateOwnUsername(pb: TypedPocketBase, username: string) {
  await pb.collection('users').update(pb.authStore.model?.id, {
    username: username,
  })
}

export function getCookie(pb: TypedPocketBase) {
  return pb.authStore.exportToCookie({ secure: false })
}
