import keycloakJs from 'https://cdn.jsdelivr.net/npm/keycloak-js@18.0.0/+esm'
import { config } from './config.js';


const loginOptions = {
  redirectUri: config.VITE_SSO_REDIRECT_URI,
  idpHint: '',
};

const _kc = new keycloakJs({
  url: `${config.VITE_SSO_AUTH_SERVER_URL}`,
  realm: `${config.VITE_SSO_REALM}`,
  clientId: `${config.VITE_SSO_CLIENT_ID}`,
});



export const initializeKeycloak = async () => {
  try {
    _kc.onTokenExpired = () => {
       console.log('Token expired, updating token...');
      _kc.updateToken();
      if (refreshed) {
        console.log('Token successfully refreshed');
      } else {
        console.warn('Token is still valid');
      }
    };
    } catch (err) {
      console.error('Failed to refresh token');
      _kc.login(loginOptions); // Redirect to login if token refresh fails
    }


    const auth = await _kc.init({
      pkceMethod: 'S256',
      checkLoginIframe: false,
    });

    if (auth) {  
      alert("Keycloak initialized with token:", _kc.token);

      // Check if token is expired
      if (_kc.isTokenExpired(30)) {
        console.log('Token is expired, updating token...');
        await _kc.updateToken(30);
      }

       // Extract state and session_state from URL
       const params = new URLSearchParams(window.location.hash.substring(1));
       const state = params.get('state');
       const sessionState = params.get('session_state');
       const code = params.get('code');
 
       console.log("State:", state);
       console.log("Session State:", sessionState);
       console.log("Code:", code);
       alert(state)
       // Store state and session state in cookies
       document.cookie = `state=${state}; path=/`;
       document.cookie = `session_state=${sessionState}; path=/`;
       document.cookie = `code=${code}; path=/`;
 
       // Redirect to /dashboard
       window.location.href = '/dashboard';


      // If the user is on the /dashboard page and not authenticated, redirect to login
      if (window.location.pathname === '/dashboard' && !auth) {
        window.location.href = '/index'; // or whatever your login route is
      }

      return _kc;
    } else {
      _kc.login(loginOptions);
    }
  }

  export const checkAuthentication = async () => {
    const auth = await _kc.init({
      pkceMethod: 'S256',
      checkLoginIframe: false,
      onLoad: 'check-sso',
    });
  
    if (!auth) {
      _kc.login(loginOptions);
    }
  };
  
  // Example usage: Protect the dashboard route
  if (window.location.pathname === '/dashboard') {
    initializeKeycloak().then((kc) => {
      if (!kc) {
        window.location.href = '/index'; // Redirect to login if not authenticated
      } else {
        console.log('User authenticated and can access dashboard');
      }
    }).catch((err) => {
      console.error('Failed to initialize Keycloak', err);
      window.location.href = '/index'; // Redirect to login on failure
    });
  }


export const logout = () => {
  window.location.href = `https://logon7.gov.bc.ca/clp-cgi/logoff.cgi?retnow=1&returl=${encodeURIComponent(
    `${config.VITE_SSO_AUTH_SERVER_URL}/realms/${config.VITE_SSO_REALM}/protocol/openid-connect/logout?post_logout_redirect_uri=` +
      config.VITE_SSO_REDIRECT_URI +
      '&client_id=' +
      config.VITE_SSO_CLIENT_ID
  )}`;
};

// Example usage
/*
initializeKeycloak().then((kc) => {
  if (kc) {
    console.log('Keycloak initialized', kc);
  }
});
*/