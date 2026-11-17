// Fixtures for rules/opengrep/typescript-web-security.yaml. Nothing here is compiled or executed.
import { provideHttpClient, withJsonpSupport, withNoXsrfProtection, HttpClientXsrfModule, HttpClientJsonpModule } from '@angular/common/http';

export const providers = [
  // ruleid: labsec.angular.xsrf-protection-disabled
  provideHttpClient(withNoXsrfProtection()),
  // ruleid: labsec.angular.jsonp-enabled
  provideHttpClient(withJsonpSupport()),
  // ok: labsec.angular.xsrf-protection-disabled
  provideHttpClient(),
];

export const legacyImports = [
  // ruleid: labsec.angular.xsrf-protection-disabled
  HttpClientXsrfModule.disable(),
  // ok: labsec.angular.xsrf-protection-disabled
  HttpClientXsrfModule.withOptions({ cookieName: 'XSRF-TOKEN' }),
];

export function legacyJsonp(http: any) {
  // ruleid: labsec.angular.jsonp-enabled
  return http.jsonp('https://api.example.test/data', 'callback');
}

export function legacyJsonpImports() {
  // ok: labsec.angular.jsonp-enabled
  return http.get('https://api.example.test/data');
}

export function storage(value: string) {
  // ruleid: labsec.typescript.browser-storage-sensitive-data
  localStorage.setItem('user_password', value);
  // ruleid: labsec.typescript.browser-storage-sensitive-data
  window.sessionStorage.setItem('apiKey', value);
  // ok: labsec.typescript.browser-storage-sensitive-data
  localStorage.setItem('theme', value);
  // ok: labsec.typescript.browser-storage-sensitive-data
  localStorage.setItem(dynamicKey, value);
}

export function verify(jwt: any, token: string, key: string) {
  // ruleid: labsec.typescript.jwt-verify-ignore-expiration
  jwt.verify(token, key, { ignoreExpiration: true });
  // ok: labsec.typescript.jwt-verify-ignore-expiration
  jwt.verify(token, key, { algorithms: ['RS256'] });
  // ok: labsec.typescript.jwt-verify-ignore-expiration
  jwt.verify(token, key, { ignoreExpiration: false });
}
