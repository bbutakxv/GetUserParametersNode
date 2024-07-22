module.exports = function(RED) {
    function GetListNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;
        node.url = config.url;
        node.login = config.login;
        node.password = config.password;

        const userSidCache = {};

        function hashPassword(password) {
            function ra() {
                return Math.floor(16 * Math.random()).toString(16);
            }
            var smt = "";
            for (var i = 0; i < 8 + 8 * Math.random(); i++) {
                smt += ra();
            }
            var md5 = require('md5');
            var passmd5 = md5(md5(md5(password).toUpperCase() + "F593B01C562548C6B7A31B30884BDE53").toUpperCase() + smt.toUpperCase()).toUpperCase() + smt.toUpperCase();
            return passmd5;
        }

        node.on('input', async function(msg) {
            if (msg.payload !== 'GetList') {
                return;
            }

            const passwordHash = hashPassword(node.password);

            if (userSidCache[node.login]) {
                node.log(`Using cached UserSID for login: ${node.login}`);
                msg.payload = {
                    login: node.login,
                    passwordHash: passwordHash,
                    userSid: userSidCache[node.login]
                };
                node.send(msg);
                return;
            }

            try {
                const fetch = await import('node-fetch');

                node.log(`Attempting to authenticate with URL: ${node.url}/Authenticate`);
                node.log(`Sending login: ${node.login} with hashed password`);

                const response = await fetch.default(`${node.url}/Authenticate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        UserName: node.login,
                        PasswordHash: passwordHash
                    })
                });

                node.log(`Response status: ${response.status}`);

                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }

                const contentType = response.headers.get('content-type');
                node.log(`Response headers: ${JSON.stringify(response.headers.raw())}`);

                if (contentType && contentType.includes('application/json')) {
                    const data = await response.json();
                    node.log(`Response data: ${JSON.stringify(data)}`);

                    if (data && data.UserSID) {
                        userSidCache[node.login] = data.UserSID;
                        msg.payload = {
                            login: node.login,
                            passwordHash: passwordHash,
                            userSid: data.UserSID
                        };
                        node.send(msg);
                    } else {
                        node.error('Authentication failed: UserSID not found in response', msg);
                    }
                } else {
                    node.error('Response is not in JSON format', msg);
                }
            } catch (error) {
                node.error('Error while fetching: ' + error.message, msg);
                node.log(`Fetch error details: ${error.stack}`);
            }
        });
    }

    RED.nodes.registerType('get-list-node', GetListNode, {
        credentials: {
            login: { type: 'text' },
            password: { type: 'password' }
        },
        settings: {
            url: { value: '', required: true }
        }
    });
};
