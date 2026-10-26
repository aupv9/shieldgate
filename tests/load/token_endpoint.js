// k6 load test for the token endpoint and the endpoints resource servers
// call on every request. Run it against a server prepared by
// scripts/conformance/serve.sh (it uses the seeded clients):
//
//   scripts/load/run.sh                   # all scenarios, via Docker
//   k6 run -e BASE_URL=http://127.0.0.1:18100 tests/load/token_endpoint.js
//
// Scenarios (select with -e SCENARIOS=a,b; default all, run one after another):
//   client_credentials  POST /oauth/token, grant_type=client_credentials
//   refresh             POST /oauth/token, grant_type=refresh_token (rotation)
//   introspect          POST /oauth/introspect of a live access token
//   discovery           GET discovery + JWKS (what every RP fetches)
//
// RATE sets the target arrival rate (iterations/s) of each scenario and
// DURATION its length. The thresholds are the pass/fail criteria recorded in
// docs/LOAD_TEST.md; they apply to requests tagged with op=<scenario>, so the
// logins that set up the refresh scenario are not measured.
//
// The refresh scenario runs on a fixed pool of REFRESH_VUS VUs. Each logs in
// (a bcrypt password check) before its first refresh; letting k6 add VUs
// when latency rises would start a feedback loop of logins. Refreshes in
// the first WARMUP seconds, while the pool logs in, are tagged
// op=refresh_warmup and not measured.
import http from 'k6/http';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';
import exec from 'k6/execution';
import { check, fail } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:18100';
const RATE = parseInt(__ENV.RATE || '200', 10);
const DURATION = __ENV.DURATION || '60s';
const SECRET = __ENV.CLIENT_SECRET || 'conformance-client-secret-0123456789';
const USER = __ENV.USER_EMAIL || 'conformance@example.com';
const PASSWORD = __ENV.USER_PASSWORD || 'Conformance-Passw0rd!';
const REFRESH_VUS = parseInt(__ENV.REFRESH_VUS || '100', 10);
const WARMUP_SECONDS = parseInt(__ENV.WARMUP || '10', 10);
const REDIRECT_URI = 'https://rp.conformance.test/callback';
// Sent on every request, so the tenant does not depend on the Host the
// server is reached at (inside Docker it is host.docker.internal)
const TENANT_ID = __ENV.TENANT_ID || 'c0f0c0f0-0000-4000-8000-000000000001';

const basicM2M = 'Basic ' + encoding.b64encode(`load-m2m:${SECRET}`);
const basicRP = 'Basic ' + encoding.b64encode(`conformance-rp:${SECRET}`);
const form = (auth, op) => ({
  headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: auth, 'X-Tenant-ID': TENANT_ID },
  tags: { op },
});

const all = ['client_credentials', 'refresh', 'introspect', 'discovery'];
const selected = (__ENV.SCENARIOS || all.join(',')).split(',').map((s) => s.trim()).filter(Boolean);

function durationSeconds(d) {
  const m = /^(\d+)(s|m)$/.exec(d);
  if (!m) throw new Error(`DURATION must look like 60s or 2m, got ${d}`);
  return parseInt(m[1], 10) * (m[2] === 'm' ? 60 : 1);
}

const scenarios = {};
const thresholds = {};
selected.forEach((name, i) => {
  if (!all.includes(name)) throw new Error(`unknown scenario ${name}`);
  scenarios[name] = {
    executor: 'constant-arrival-rate',
    exec: name,
    rate: RATE,
    timeUnit: '1s',
    duration: DURATION,
    preAllocatedVUs: name === 'refresh' ? REFRESH_VUS : Math.max(20, Math.ceil(RATE / 2)),
    maxVUs: name === 'refresh' ? REFRESH_VUS : Math.max(100, RATE * 2),
    startTime: `${i * (durationSeconds(DURATION) + 5)}s`,
  };
  thresholds[`http_req_failed{op:${name}}`] = ['rate<0.01'];
  thresholds[`http_req_duration{op:${name}}`] = name === 'discovery' ? ['p(95)<50'] : ['p(95)<250'];
  thresholds[`checks{op:${name}}`] = ['rate>0.99'];
  // Iterations dropped while the refresh pool logs in say nothing about
  // refresh capacity, so that scenario is judged by its latency only
  if (name !== 'refresh') {
    thresholds[`dropped_iterations{scenario:${name}}`] = [`count<${Math.ceil(RATE * durationSeconds(DURATION) * 0.01)}`];
  }
});

export const options = {
  scenarios,
  thresholds,
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export function setup() {
  if (!selected.includes('introspect')) return { accessToken: '' };
  const res = http.post(`${BASE_URL}/oauth/token`, { grant_type: 'client_credentials', scope: 'read' }, form(basicM2M, 'setup'));
  if (res.status !== 200) fail(`setup: client_credentials failed: ${res.status} ${res.body}`);
  return { accessToken: res.json('access_token') };
}

export function client_credentials() {
  const res = http.post(`${BASE_URL}/oauth/token`, { grant_type: 'client_credentials', scope: 'read' }, form(basicM2M, 'client_credentials'));
  check(res, { 'token issued': (r) => r.status === 200 && !!r.json('access_token') }, { op: 'client_credentials' });
}

// Each VU logs in once and then owns its chain of rotating refresh tokens:
// a VU runs one iteration at a time, so no refresh token is ever presented
// twice (reuse would revoke the whole family, by design)
let refreshToken = '';
export function refresh() {
  if (!refreshToken) refreshToken = login().refresh_token;
  const warm = Date.now() - exec.scenario.startTime >= WARMUP_SECONDS * 1000;
  const op = warm ? 'refresh' : 'refresh_warmup';
  const res = http.post(`${BASE_URL}/oauth/token`, { grant_type: 'refresh_token', refresh_token: refreshToken }, form(basicRP, op));
  const ok = check(res, { 'refresh rotated': (r) => r.status === 200 && !!r.json('refresh_token') }, { op });
  // On failure the chain is dead; the next iteration starts a new one
  refreshToken = ok ? res.json('refresh_token') : '';
}

export function introspect(data) {
  const res = http.post(`${BASE_URL}/oauth/introspect`, { token: data.accessToken }, form(basicM2M, 'introspect'));
  check(res, { 'token active': (r) => r.status === 200 && r.json('active') === true }, { op: 'introspect' });
}

export function discovery() {
  const params = { tags: { op: 'discovery' } };
  const responses = http.batch([
    ['GET', `${BASE_URL}/.well-known/openid-configuration`, null, params],
    ['GET', `${BASE_URL}/.well-known/jwks.json`, null, params],
  ]);
  check(responses[0], { 'discovery ok': (r) => r.status === 200 }, { op: 'discovery' });
  check(responses[1], { 'jwks ok': (r) => r.status === 200 && r.json('keys').length > 0 }, { op: 'discovery' });
}

// login runs the authorization code + PKCE flow for conformance-rp, filling
// in the login form and, the first time, the consent form
function login() {
  const verifier = encoding.b64encode(crypto.randomBytes(32), 'rawurl');
  const challenge = encoding.b64encode(crypto.sha256(verifier, 'binary'), 'rawurl');
  const query = 'response_type=code&client_id=conformance-rp&scope=openid%20read&state=s&nonce=n' +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code_challenge=${challenge}&code_challenge_method=S256`;
  const params = { redirects: 0, headers: { 'X-Tenant-ID': TENANT_ID }, tags: { op: 'login' } };

  let res = http.get(`${BASE_URL}/oauth/authorize?${query}`, params);
  res = http.post(`${BASE_URL}/oauth/login`, Object.assign(hiddenFields(res.body), { username: USER, password: PASSWORD }), params);
  if (res.status === 200) {
    res = http.post(`${BASE_URL}/oauth/consent`, Object.assign(hiddenFields(res.body), { decision: 'allow' }), params);
  }
  const code = (/[?&]code=([^&]+)/.exec(res.headers.Location || '') || [])[1];
  if (!code) fail(`login did not return a code (status ${res.status})`);

  res = http.post(`${BASE_URL}/oauth/token`,
    { grant_type: 'authorization_code', code: decodeURIComponent(code), redirect_uri: REDIRECT_URI, code_verifier: verifier },
    form(basicRP, 'login'));
  if (res.status !== 200) fail(`code exchange failed: ${res.status} ${res.body}`);
  return res.json();
}

function hiddenFields(body) {
  const fields = {};
  const re = /<input type="hidden" name="([^"]+)" value="([^"]*)"/g;
  let m;
  while ((m = re.exec(body || '')) !== null) {
    fields[m[1]] = m[2].replace(/&#43;/g, '+').replace(/&#34;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
  }
  return fields;
}
