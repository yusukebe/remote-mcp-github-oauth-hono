import { env } from 'cloudflare:workers'
import type { AuthRequest, OAuthHelpers } from '@cloudflare/workers-oauth-provider'
import { Hono } from 'hono'
import { githubAuth } from '@hono/oauth-providers/github'
import { clientIdAlreadyApproved, parseRedirectApproval, renderApprovalDialog } from './workers-oauth-utils'
import { createMiddleware } from 'hono/factory'

const app = new Hono<{
	Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers }
	Variables: {
		token?: string
	}
}>()

app.get('/authorize', async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw)
	const { clientId } = oauthReqInfo
	if (!clientId) {
		return c.text('Invalid request', 400)
	}

	if (await clientIdAlreadyApproved(c.req.raw, oauthReqInfo.clientId, env.COOKIE_ENCRYPTION_KEY)) {
		return c.redirect(`/callback?state=${btoa(JSON.stringify(oauthReqInfo))}`)
	}

	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		server: {
			description: 'This is a demo MCP Remote Server using GitHub for authentication.',
			logo: 'https://avatars.githubusercontent.com/u/314135?s=200&v=4',
			name: 'Cloudflare GitHub MCP Server' // optional
		},
		state: { oauthReqInfo } // arbitrary data that flows through the form submission below
	})
})

const githubAuthMiddleware = (state?: string) =>
	createMiddleware(async (c, next) => {
		return await githubAuth({
			// `state` option is not available in the current OAuth Provider Middleware.
			// You should patch it.
			state,
			client_id: c.env.GITHUB_CLIENT_ID,
			client_secret: c.env.GITHUB_CLIENT_SECRET,
			scope: ['read:user', 'user:email'],
			oauthApp: true
		})(c, next)
	})

app.post('/authorize', async (c, next) => {
	const { state } = await parseRedirectApproval(c.req.raw, c.env.COOKIE_ENCRYPTION_KEY)
	return await githubAuthMiddleware(btoa(JSON.stringify(state.oauthReqInfo)))(c, next)
})

// GitHub OAuth middleware configuration
app.get('/callback', githubAuthMiddleware(), async (c) => {
	const oauthReqInfo = JSON.parse(atob(c.req.query('state') as string)) as AuthRequest
	if (!oauthReqInfo.clientId) {
		return c.text('Invalid state', 400)
	}
	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		props: {
			accessToken: c.var.token.token
		},
		request: oauthReqInfo,
		scope: oauthReqInfo.scope
	})

	return c.redirect(redirectTo)
})

export default app
