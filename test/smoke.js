/**
 * Requests the endpoints of a proxy that runs on this host, and exits 1 on the first difference.
 * The CI image job runs it in the container: `docker exec <container> /nodejs/bin/node test/smoke.js`.
 * It is not a jest test: the name does not end in .test.js.
 */

const BASE = process.env.SMOKE_BASE_URL || 'http://127.0.0.1:3000';

const CHECKS = [
    // The error page comes from views/error.pug. Without the view, Express sends a plain 404.
    { path: '/nope', status: 404, body: 'font-family' },
    { path: '/wsfed', status: 400, body: 'font-family' },
    { path: '/wsfed?wa=wsignin1.0&wtrealm=https://exchange.example.com/owa/', status: 302, location: 'https://idp.example.com/saml?SAMLRequest=' },
    { path: '/FederationMetadata/2007-06/FederationMetadata.xml', status: 200, body: 'EntityDescriptor' },
];

async function waitUntilUp() {
    for (let attempt = 0; attempt < 50; attempt++) {
        try {
            await fetch(BASE + '/nope');
            return;
        } catch {
            await new Promise((resolve) => setTimeout(resolve, 200));
        }
    }
    throw new Error(`no answer from ${BASE} after 10 seconds`);
}

async function main() {
    await waitUntilUp();
    for (const check of CHECKS) {
        const res = await fetch(BASE + check.path, { redirect: 'manual' });
        const body = await res.text();
        const location = res.headers.get('location') || '';
        const problems = [];
        if (res.status !== check.status) problems.push(`status ${res.status}, expected ${check.status}`);
        if (check.body && !body.includes(check.body)) problems.push(`body does not contain "${check.body}"`);
        if (check.location && !location.startsWith(check.location)) problems.push(`location is "${location}"`);
        if (!res.headers.get('content-security-policy')) problems.push('no Content-Security-Policy header');
        if (problems.length > 0) {
            throw new Error(`${check.path}: ${problems.join('; ')}`);
        }
        console.log(`ok ${res.status} ${check.path}`);
    }
}

main().catch((err) => {
    console.error(`FAIL ${err.message}`);
    process.exitCode = 1;
});
