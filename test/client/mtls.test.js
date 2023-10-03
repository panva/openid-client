const fs = require('fs');
const path = require('path');

const { expect } = require('chai');
const nock = require('nock');
const jose = require('jose');

const { Issuer, custom } = require('../../lib');
const clientHelpers = require('../../lib/helpers/client');

const fail = () => {
  throw new Error('expected promise to be rejected');
};
const issuer = new Issuer({
  issuer: 'https://op.example.com',
  userinfo_endpoint: 'https://op.example.com/me',
  token_endpoint: 'https://op.example.com/token',
  introspection_endpoint: 'https://op.example.com/token/introspect',
  revocation_endpoint: 'https://op.example.com/token/revoke',
  mtls_endpoint_aliases: {
    userinfo_endpoint: 'https://mtls.op.example.com/me',
    token_endpoint: 'https://mtls.op.example.com/token',
    introspection_endpoint: 'https://mtls.op.example.com/token/introspect',
    revocation_endpoint: 'https://mtls.op.example.com/token/revoke',
  },
});

const cert = `-----BEGIN CERTIFICATE-----
MIIFUDCCAzigAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgYExCzAJBgNVBAYTAkdC
MRAwDgYDVQQIDAdFbmdsYW5kMRIwEAYDVQQKDAlBbGljZSBMdGQxKDAmBgNVBAsM
H0FsaWNlIEx0ZCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgNVBAMMGUFsaWNl
IEx0ZCBJbnRlcm1lZGlhdGUgQ0EwHhcNMTgwOTIxMTU1NTAwWhcNMTkxMDAxMTU1
NTAwWjCBizELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTESMBAGA1UEBwwJ
U3RyYXNuaWNlMRAwDgYDVQQKDAdCb2IgTHRkMRQwEgYDVQQLDAtFbmdpbmVlcmlu
ZzERMA8GA1UEAwwIY2xpZW50aWQxHDAaBgkqhkiG9w0BCQEWDXBhbnZhQGJvYi5s
dGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHZbAIXt6QFLYhBql9
pWBZx1R7A12o7gV5huVVeVEV9g+pmXdKU1Jq/OrQgNsS1ScY3cRqx6HLqmBxVh5w
rQ6g02d1QV2+RHJopC1kg7B4/pznfj44JxW0HQmSYYi+ATvfyuzBU+Rax87ALinL
r5gZTB69W/9Pr9smPbGHr3UM1mHz8Kd8Wvs494EQo/u7ivvbV8Kr8oR5VgsBCTMQ
A7fla7TxX8ObgRNSmwG/Sjr1Dv2baqGvuhQ70tqiZRRo1uuHjwOUzpQeF9LdFniK
HwhjnLlFucVK6inDZ2VD/oJyEOq4/pjTFemB6QgRNyqKUmd8lpenVSuujJ7TJNEy
Vw33AgMBAAGjgcUwgcIwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBaAwMwYJ
YIZIAYb4QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIENsaWVudCBDZXJ0aWZpY2F0
ZTAdBgNVHQ4EFgQUoT7Nh2gJLqlru7QH7sSgxBaNcOswHwYDVR0jBBgwFoAU9aXg
CTQVzkjeGVwlbmtKkYn5/rIwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAgEAqjXoNfaOG1Kxk9jO
vrHfTNdgGdrpaudZH4gRU2044m8JvazUxhnWgk+n4mkjVD5CrNu7FWza3twt2nIR
50GKWilg2fiBIPcH5RVYz7gdO3r2N1nWohx3P49bGEyyDwxR1aeM/O8w0gQ70Ayd
oPPKggpef61MsLgYl+tiVqKx3VHO5A6hPScH26p56DOq28fjLZPnTskoXxn1IHB4
Ea4fUC1x4gXDS38qvvcBVWmQWbeTm1dWEUsmRVp6D1jPAsikYjzb86lOzC0S7V6l
X1QwAL4nxDsBpxx1JlKeNDk5sdr7mHQtODjq8w+Uo0EPmgGdTsCiBgPfWHRgYAs9
HTFbC6FWeu+Bu2Nfuo8MAYCY2+FhGEwUHuUtYUR04V9F6+J4xmSsPZp46PNo4F2u
gL4Nm81py3eDOq9WcuoN0iB8XqcjmFb3BvirpSzmNuP1FsqDj+QGN73W/seHylFM
AGnsAaF3A3gBUFF26+xz7hSXLGbEhoR6FYBZKvLBQgS3zna6KbYdw0pqUBvrEJfr
VXCQPy/Y1C3EnEhQqJDx9Rmw5qm6RpuCPga4pDzQPBLny+ggmb4BqHieD+Xz3g0b
N/84lxiSg60mlyuEwOHcQMmlOxjYf2zliCqRptD/LlfITlmzGjds9BhLlkHIBR3I
kEejZluclYP0Dljd65DCTqY1z0c=
-----END CERTIFICATE-----`;

const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx2WwCF7ekBS2IQapfaVgWcdUewNdqO4FeYblVXlRFfYPqZl3
SlNSavzq0IDbEtUnGN3Easehy6pgcVYecK0OoNNndUFdvkRyaKQtZIOweP6c534+
OCcVtB0JkmGIvgE738rswVPkWsfOwC4py6+YGUwevVv/T6/bJj2xh691DNZh8/Cn
fFr7OPeBEKP7u4r721fCq/KEeVYLAQkzEAO35Wu08V/Dm4ETUpsBv0o69Q79m2qh
r7oUO9LaomUUaNbrh48DlM6UHhfS3RZ4ih8IY5y5RbnFSuopw2dlQ/6CchDquP6Y
0xXpgekIETcqilJnfJaXp1Urroye0yTRMlcN9wIDAQABAoIBABT9hGltKzq5o26Y
l/ENHrZ0wFTuxsZIwDTJ2YyE599K9t0gtakSWmO+2i0201kJLUN13P5so4CgH+Tu
bufnn9mYR5TVW7vy0qRnXAvvvP0PuI66AGzC2IsMX3yUXeO6l4X4g7HaVfikfgRH
F8lEY9uN4tKGQ7ssxQIijnS9KLJAE6A+zVBA3NVvq4oXSxcyiSlEb7drmOe/2Ibr
srC2pnFAZy+XEJ8sIi1o2BXoz70bJkCaryi5gs+01v6Yi8oE72h/YNSZRMahr5Hl
CznXdOsmNAQ23zgDhi0UhtH5+5Xxi3k9dT8wxT4B14YDmw3sAmoUfbYwj3xWlQ3t
l4QofRkCgYEA4feLw/LgbRd94yunKm8IsaZ8ISUjazjgftKOtk1oxedsbIJyq+F/
rfO7XOMqsGyF1gNpXtDJaSJgSngqOwG13lk8MWtpGjqChkkmHHvMBK8IIWLkE/fu
reQ68V5BDA51PJf8HpLxEAgpH64s9wa1WtBXHO2ZppweMxjJVBO7nFUCgYEA4eYd
Nvz8WgWNUkeWLGC++7ublc5gXBr9kioXbTJ4Pp8Va2Ngaa/PZm0yMDSD9xxpHkCC
ZtlsZlUXVBwldh8A8C841YCOgJvprC4+UQobGndsgwQ8KmhwjIKj5z5uxm5mwBi8
xdmnfJF+sP3hwJMfK7DaS/uWRs98874eSHloTRsCgYBaV7hffUlRFGVWX+uTwZS+
Qgu6zLhec/z9d31rUYOkLCRjNbxXD+8WQy4TsxcsNhdEO1TzfZIpIH9TBrwLn2Fx
Jkg0kfcRb3cj7Tb5iF1HOhuMDZeWjDe2+lq+iaqEAXvJ4BICv0j12e1nJyH/GYWE
a2uIu04FGMHSOAS2QrVtiQKBgAVjMpEsKWyQM1WiBW/bgtKIH+bLvDqWHjQNMu/U
w09jBeTAwvziR4T+17KUng0XrV4eVb3UM6ShJORJo48UoDYaOjXFUiC5FzKXC79t
CUZxULIzOKgeQ4jmWLhcIdIzsdmk/WOOlFMBOU9JTsgD+jtVhW9IecYIjsdVYm2C
D72/AoGAIYwlwstX7x5dlJOVe9ytMBkbuFKdycGvVxjEzvHkjzrpxUY3v/lVRBFN
Ym+FYK6KtEjrawUvE9CwzkoXiQbisQsGkp1sJxYDkDzW1jf50T3DOOCbGmW6bi7H
2LZBr34osdcugbFGO07Y8gAiRrh+lbv1JBzALHt93QSVeN9mPNY=
-----END RSA PRIVATE KEY-----`;

const pfx = fs.readFileSync(path.join(__dirname, 'testcert.p12'));

describe('mutual-TLS', () => {
  beforeEach(function () {
    this.client = new issuer.Client({
      client_id: 'client',
      token_endpoint_auth_method: 'self_signed_tls_client_auth',
      tls_client_certificate_bound_access_tokens: true,
    });
    this.client[custom.http_options] = () => ({ key, cert });
    this.jwtAuthClient = new issuer.Client({
      client_id: 'client',
      client_secret: 'secret',
      token_endpoint_auth_method: 'client_secret_jwt',
      token_endpoint_auth_signing_alg: 'HS256',
      tls_client_certificate_bound_access_tokens: true,
    });
    this.jwtAuthClientNoSenderConstraining = new issuer.Client({
      client_id: 'client',
      client_secret: 'secret',
      token_endpoint_auth_method: 'client_secret_jwt',
      token_endpoint_auth_signing_alg: 'HS256',
      tls_client_certificate_bound_access_tokens: false,
    });
    this.client[custom.http_options] = () => ({ key, cert });
  });

  it('uses the issuer identifier and token endpoint as private_key_jwt audiences', async function () {
    let {
      form: { client_assertion: jwt },
    } = await clientHelpers.authFor.call(this.jwtAuthClient, 'token');
    let { aud } = jose.decodeJwt(jwt);
    expect(aud).to.deep.equal(['https://op.example.com', 'https://op.example.com/token']);
    ({
      form: { client_assertion: jwt },
    } = await clientHelpers.authFor.call(this.jwtAuthClient, 'introspection'));
    ({ aud } = jose.decodeJwt(jwt));
    expect(aud).to.deep.equal(['https://op.example.com', 'https://op.example.com/token']);
    ({
      form: { client_assertion: jwt },
    } = await clientHelpers.authFor.call(this.jwtAuthClient, 'revocation'));
    ({ aud } = jose.decodeJwt(jwt));
    expect(aud).to.deep.equal(['https://op.example.com', 'https://op.example.com/token']);
  });

  it('requires mTLS for userinfo when tls_client_certificate_bound_access_tokens is true', async function () {
    nock('https://mtls.op.example.com').get('/me').reply(200, { sub: 'foo' });

    await this.client.userinfo('foo');

    delete this.client[custom.http_options];

    try {
      await this.client.userinfo('foo');
      fail();
    } catch (err) {
      expect(err.message).to.eql('mutual-TLS certificate and key not set');
    }
  });

  it('requires mTLS for introspection authentication when introspection_endpoint_auth_method is tls_client_auth', async function () {
    nock('https://mtls.op.example.com').post('/token/introspect').reply(200, {});

    await this.client.introspect('foo');

    delete this.client[custom.http_options];

    try {
      await this.client.introspect('foo');
      fail();
    } catch (err) {
      expect(err.message).to.eql('mutual-TLS certificate and key not set');
    }
  });

  it('requires mTLS for revocation authentication when revocation_endpoint_auth_method is tls_client_auth', async function () {
    nock('https://mtls.op.example.com').post('/token/revoke').reply(200, {});

    await this.client.revoke('foo');

    delete this.client[custom.http_options];

    try {
      await this.client.revoke('foo');
      fail();
    } catch (err) {
      expect(err.message).to.eql('mutual-TLS certificate and key not set');
    }
  });

  it('works with a PKCS#12 file and a passphrase', async function () {
    this.client[custom.http_options] = () => ({ pfx });

    nock('https://mtls.op.example.com').get('/me').reply(200, { sub: 'foo' });

    await this.client.userinfo('foo');

    delete this.client[custom.http_options];

    try {
      await this.client.userinfo('foo');
      fail();
    } catch (err) {
      expect(err.message).to.eql('mutual-TLS certificate and key not set');
    }
  });
});
