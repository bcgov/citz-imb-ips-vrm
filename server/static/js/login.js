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
        _kc.updateToken()
      }

    const auth = await _kc.init({
      pkceMethod: 'S256',
      checkLoginIframe: false,
      silentCheckSsoFallback: false,
      onLoad: 'login-required',
    })

    if (auth) {
      alert("alert!!!!!!!!!!!!!!!!!");
      window.location.href = '/dashboard';
        return _kc
    } else {
      alert("non alert!!!!!!!!!!!!!!!")
        _kc.login(loginOptions)
    }
  } catch (err) {
    console.log(err)
  }
}

// since we have to perform logout at siteminder, we cannot use keycloak-js logout method so manually triggering logout through a function
// if using post_logout_redirect_uri, then either client_id or id_token_hint has to be included and post_logout_redirect_uri need to match
// one of valid post logout redirect uris in the client configuration
export const logout = () => {
  window.location.href = `https://logon7.gov.bc.ca/clp-cgi/logoff.cgi?retnow=1&returl=${encodeURIComponent(
    `${config.VITE_SSO_AUTH_SERVER_URL}/realms/${config.VITE_SSO_REALM}/protocol/openid-connect/logout?post_logout_redirect_uri=` +
      config.VITE_SSO_REDIRECT_URI +
      '&client_id=' +
      config.VITE_SSO_CLIENT_ID
  )}`;
};