/**
 * bin/www as a child process: startup errors and the signal handling.
 * All certificate and key settings point to the fixtures: certs/ is empty in a clean
 * checkout and in the image build, and a test must not read a real signing key.
 */

const { spawn } = require('child_process');
const net = require('net');
const path = require('path');

const WWW = path.join(__dirname, '../../bin/www');
const ENV = {
    PATH: process.env.PATH,
    DEBUG: 'ws-fed-saml-proxy:server',
    WSFED_ALLOWED_REALMS: 'https://exchange.corp',
    SAML2_IDP_PUB_KEY: '../test/fixtures/test-cert.pem',
    WSFED_CERT: '../test/fixtures/test-cert.pem',
    WSFED_KEY: '../test/fixtures/test-cert.key',
    WSFED_PKCS7: '../test/fixtures/test-cert.pem',
};

function freePort() {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.once('error', reject);
        srv.listen(0, '127.0.0.1', () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
    });
}

const children = [];
afterEach(() => {
    // a child that does not exit on its own must not outlive the test
    for (const child of children.splice(0)) {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
});

function start(env) {
    const child = spawn(process.execPath, [WWW], { env: { ...ENV, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
    const listening = new Promise((resolve, reject) => {
        child.stderr.on('data', () => { if (stderr.includes('Listening on')) resolve(); });
        child.once('exit', () => reject(new Error(`exited before listening:\n${stderr}`)));
    });
    // a test that expects an early exit never awaits `listening`
    listening.catch(() => {});
    return { child, exited, listening, stderr: () => stderr };
}

describe('bin/www', () => {
    test('a PORT that is not a number is fatal', async () => {
        const run = start({ PORT: 'abc' });
        const timeout = new Promise((_resolve, reject) => setTimeout(() => reject(new Error('still running: ' + run.stderr())), 4000).unref());
        const { code } = await Promise.race([run.exited, timeout]);
        expect(code).toBe(1);
        expect(run.stderr()).toMatch(/FATAL: PORT/);
    });

    test('SIGTERM closes the server and exits 0', async () => {
        const run = start({ PORT: String(await freePort()) });
        await run.listening;
        run.child.kill('SIGTERM');
        const { code, signal } = await run.exited;
        expect(signal).toBeNull();
        expect(code).toBe(0);
    }, 15000);
});
