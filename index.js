const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const pkg = require("./package.json");

const createCipheriv = crypto.createCipheriv;
const createDecipheriv = crypto.createDecipheriv;
const randomBytes = crypto.randomBytes;

let jwtSecret = "Secret (this will be overridden by user at launch)";
let passSecret = "Secret (this will be overridden by user at launch)";

const encrypt = async (password) => {
    const iv = Buffer.from(randomBytes(16));
    const cipher = createCipheriv("aes-256-gcm", Buffer.from(passSecret), iv);
    const encpass = Buffer.concat([cipher.update(password), cipher.final()]);
    return {
        iv: iv.toString("hex"),
        password: encpass.toString("hex"),
        tag: cipher.getAuthTag().toString("hex")
    };
};

const decrypt = async (encpass) => {
    const decipher = createDecipheriv(
        "aes-256-gcm",
        Buffer.from(passSecret),
        Buffer.from(encpass.iv, "hex")
    );
    decipher.setAuthTag(Buffer.from(encpass.tag, "hex"));
    const decpass = Buffer.concat([decipher.update(Buffer.from(encpass.password, "hex")), decipher.final()]);
    return decpass.toString();
};

const EncryptionTools = {
    /**
     * @param {string} password Password to be encrypted
     * @returns Signed JsonWebToken
     */
    encryptPassword: async (password) => {
        const encryptedPass = await encrypt(password);
        const token = jwt.sign(encryptedPass, jwtSecret);
        return token;
    },
    /**
     * 
     * @param {string} token JsonWebToken
     * @returns Decrypted password
     */
    decryptPassword: async (token) => {
        const isTrusted = jwt.verify(token, jwtSecret);
        if (isTrusted) {
            const decoded = jwt.decode(token);
            return await decrypt(decoded);
        }
    }
}

const readLine = require("readline").createInterface({ input: process.stdin, output: process.stdout });

console.log(`${pkg.name} - v${pkg.version} - Author: ${pkg.author}\n`);

readLine.question("Mode (enc / dec)\n> ", (mode) => {
    if (mode === "enc") {
        readLine.question("Enter a JWT secret.\n> ", (secret) => {
            jwtSecret = secret;
            readLine.question("Enter a password secret (32 bytes - 32 chars).\n> ", (secret) => {
                if (secret.length !== 32) {
                    console.log("Password secret must be 32 characters (32 bytes)!");
                    return readLine.close();
                }
                passSecret = secret;
                readLine.question("Enter a password you would like to be encrypted.\n> ", async (data) => {
                    const jwt = await EncryptionTools.encryptPassword(data);
                    console.log(`\nYour JSONWebToken is: ${jwt}`);
                    readLine.close();
                });
            });
        });
    } else if (mode === "dec") {
        readLine.question("Enter a JWT secret.\n> ", (secret) => {
            jwtSecret = secret;
            readLine.question("Enter a password secret.\n> ", (secret) => {
                if (secret.length !== 32) {
                    console.log("Password secret must be 32 characters (32 bytes)!");
                    return readLine.close();
                }
                passSecret = secret;
                readLine.question("Enter the JWT that contains encrypted password object.\n> ", async (data) => {
                    const jwt = await EncryptionTools.decryptPassword(data);
                    console.log(`\nYour decrypted password is: ${jwt}`);
                    readLine.close();
                });
            });
        });
    } else {
        console.log("Invalid mode (must be enc / dec)");
        process.exit(1);
    }
})



readLine.on('close', () => console.log("\n Done!"));