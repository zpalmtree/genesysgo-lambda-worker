var https = require('https');
var nacl = require('tweetnacl');
var solana = require('@solana/web3.js');
var bs58 = require('bs58');

function httpsPost({ body, ...options }) {
    return new Promise((resolve,reject) => {
        const req = https.request({ method: 'POST', ...options, }, (res) => {
            const chunks = [];

            res.on('data', data => chunks.push(data));
            res.on('end', () => {
                const resBody = Buffer.concat(chunks);
                resolve({ body: resBody, statusCode: res.statusCode });
            })
        });

        req.on('error', reject);

        if (body) {
            req.write(body);
        }

        req.end();
    });
}

exports.handler = async (event) => {
    try {
        console.log('Creating login message');

        const wallet = solana.Keypair.fromSecretKey(new Uint8Array(JSON.parse(process.env.SECRET_KEY)));

        const loginMessage = new TextEncoder().encode(`Sign in to GenesysGo Shadow Platform.`);

        console.log('Signing login message');

        const signer = wallet.publicKey.toString();

        console.log(`Signer: ${signer}`);

        const encodedMessage = bs58.encode(nacl.sign.detached(loginMessage, wallet.secretKey));
        const loginBody = {
            message: encodedMessage,
            signer,
        };

        console.log('Logging into genesysgo');

        const loginResponse = await httpsPost({
            hostname: 'portal.genesysgo.net',
            path: '/api/signin',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(loginBody),
        });

        if (loginResponse.statusCode !== 200) {
            return {
                statusCode: loginResponse.statusCode,
                body: JSON.stringify({
                    error: `Got unexpected status code attempting to login to genesysgo: ${loginResponse.body}!`,
                }),
            };
        }

        const authResponse = JSON.parse(loginResponse.body);

        if (authResponse.user.publicKey !== signer) {
            return {
                statusCode: 500,
                body: JSON.stringify({
                    error: `Logged in as unexpected user: ${authResponse.user.publicKey}`,
                }),
            };
        }

        const authenticationToken = authResponse.token;

        console.log(`Successfully acquired authentication token.`);

        console.log('Requesting JWT token');

        console.log(`RPC ID: ${process.env.RPC_ID}`);

        const { statusCode, body } = await httpsPost({
            hostname: 'portal.genesysgo.net',
            path: `/api/premium/token/${process.env.RPC_ID}`,
            headers: {
                Authorization: `Bearer ${authenticationToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                user: signer,
            }),
        });

        if (statusCode !== 200) {
            return {
                statusCode,
                body: JSON.stringify({
                    error: `Got unexpected status code attempting to fetch JWT token: ${body}!`,
                }),
            };
        }

        const parsedToken = JSON.parse(body);

        if (typeof parsedToken.token !== "string") {
            console.log("No valid jwt token returned");

            return {
                statusCode: 500,
                body: JSON.stringify({
                    jwt: undefined,
                    error: 'Could not fetch valid JWT token!',
                }),
            }
        }

        const JWT = parsedToken.token;

        return {
            statusCode: 200,
            body: JSON.stringify({
                jwt: JWT,
                error: undefined,
            }),
        }
    } catch (err) {
        return {
            statusCode: 500,
            body: JSON.stringify({
                jwt: undefined,
                error: err.toString(),
            }),
        };
    }
}
