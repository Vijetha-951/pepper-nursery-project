// Google OAuth Configuration
export const GOOGLE_CLIENT_ID = process.env.REACT_APP_GOOGLE_CLIENT_ID || "your-google-client-id.apps.googleusercontent.com";

export const googleConfig = {
  clientId: GOOGLE_CLIENT_ID,
  redirectUri: process.env.NODE_ENV === 'production' 
    ? 'https://your-domain.com/auth/google/callback'
    : 'http://localhost:3000/auth/google/callback',
  scope: [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
  ].join(' ')
};

// Google OAuth URLs
export const getGoogleAuthUrl = () => {
  const baseUrl = 'https://accounts.google.com/oauth/authorize';
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: googleConfig.redirectUri,
    scope: googleConfig.scope,
    response_type: 'code',
    access_type: 'offline',
    prompt: 'consent'
  });
  
  return `${baseUrl}?${params.toString()}`;
};