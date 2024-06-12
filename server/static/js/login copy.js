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
       alert("state: ",state)

       // Store state and session state in cookies
       document.cookie = `state=${state}; path=/`;
       document.cookie = `session_state=${sessionState}; path=/`;
       document.cookie = `code=${code}; path=/`;

      return _kc;
    } else {
      _kc.login(loginOptions);
    }
  }

  export const checkAuthentication = async () => {
    // if test environment (localhost)
    if (window.location.hostname == "localhost") {
      if (document.cookie.indexOf("state=") < 0) {
        alert("no authed");
        window.location.href = '/';
      } else {
        alert ("authed! (on localhost)");

        // Redirect to /dashboard
        let dashboard_uri = "/dashboard";
        if (window.location.pathname != dashboard_uri) {
          window.location.href = dashboard_uri;
        }
      }

      return;
    }

    // if real environment
    const auth = await _kc.init({
      pkceMethod: 'S256',
      checkLoginIframe: false,
      onLoad: 'check-sso',
    });
  
    if (!auth) {
      alert("no authed");
      window.location.href = '/';
    } else {
      // check parameters
      alert('authed : ', window.location.hash);

       // Redirect to /dashboard
       let dashboard_uri = "/dashboard";
       if (window.location.pathname != dashboard_uri) {
        window.location.href = dashboard_uri;
       }

      /*
      // If the user is on the /dashboard page and not authenticated, redirect to login
      if (window.location.pathname === '/dashboard' && !auth) {
        window.location.href = '/'; // or whatever your login route is
      }
      */
    }
  };
  
  // check is it authenticated?
  checkAuthentication();

  // Example usage: Protect the dashboard route
  /*
  if (window.location.pathname != '/') {
    initializeKeycloak().then((kc) => {
      if (!kc) {
        alert("no auth");

        window.location.href = '/'; // Redirect to login if not authenticated
      } else {
        alert("authed");

        //console.log('User authenticated and can access dashboard');
        let dashboard_uri = "/dashboard";
        if (window.location.pathname != dashboard_uri) {
         window.location.href = dashboard_uri;
        }
      }
    }).catch((err) => {
      console.error('Failed to initialize Keycloak', err);
      window.location.href = '/'; // Redirect to login on failure
    });
  }
*/

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