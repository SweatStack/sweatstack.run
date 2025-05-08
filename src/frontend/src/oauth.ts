// OAuth2 configuration
const config = {
  // TODO: Replace these with your actual OAuth2 provider details
  clientId: 'e157df3e4ebd48d1',
  authorizationEndpoint: 'https://app.sweatstack.no/oauth/authorize',
  tokenEndpoint: 'https://app.sweatstack.no/api/v1/oauth/token',
  redirectUri: window.location.href,
  scope: 'data:read',
}

// Generate a random string for PKCE code verifier
function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  window.crypto.getRandomValues(array)
  return base64URLEncode(array)
}

// Generate code challenge from verifier
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await window.crypto.subtle.digest('SHA-256', data)
  return base64URLEncode(new Uint8Array(digest))
}

// Base64URL encode
function base64URLEncode(buffer: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// Generate state parameter for CSRF protection
function generateState(): string {
  const array = new Uint8Array(16)
  window.crypto.getRandomValues(array)
  return base64URLEncode(array)
}

// Store PKCE values in session storage
function storePKCEValues(codeVerifier: string, state: string) {
  sessionStorage.setItem('pkce_code_verifier', codeVerifier)
  sessionStorage.setItem('oauth_state', state)
}

// Get stored PKCE values
function getStoredPKCEValues(): { codeVerifier: string; state: string } | null {
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier')
  const state = sessionStorage.getItem('oauth_state')
  if (!codeVerifier || !state) return null
  return { codeVerifier, state }
}

// Clear stored PKCE values
function clearStoredPKCEValues() {
  sessionStorage.removeItem('pkce_code_verifier')
  sessionStorage.removeItem('oauth_state')
}

// Initiate OAuth2 flow
export async function initiateOAuth2Flow() {
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = await generateCodeChallenge(codeVerifier)
  const state = generateState()
  
  storePKCEValues(codeVerifier, state)
  
  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    prompt: 'none',
  })
  
  window.location.href = `${config.authorizationEndpoint}?${params.toString()}`
}

// Handle OAuth2 callback
export async function handleOAuth2Callback(): Promise<string | null> {
  const params = new URLSearchParams(window.location.search)
  const code = params.get('code')
  const state = params.get('state')
  const storedValues = getStoredPKCEValues()
  
  if (!code || !state || !storedValues) {
    return null
  }
  
  if (state !== storedValues.state) {
    console.error('State mismatch - possible CSRF attack')
    return null
  }
  
  try {
    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: config.clientId,
        code_verifier: storedValues.codeVerifier,
        code: code,
        redirect_uri: config.redirectUri,
      }),
    })
    
    if (!response.ok) {
      throw new Error('Token request failed')
    }
    
    const data = await response.json()
    clearStoredPKCEValues()
    
    // Remove the authorization code from the URL
    const newUrl = window.location.pathname
    window.history.replaceState({}, document.title, newUrl)
    
    return data.access_token
  } catch (error) {
    console.error('Error exchanging code for token:', error)
    return null
  }
}

// Check if we're in the OAuth callback
export function isOAuthCallback(): boolean {
  return window.location.search.includes('code=')
} 