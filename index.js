const crypto = require("crypto");
const pkg = require("./package.json");

const createCipheriv = crypto.createCipheriv;
const createDecipheriv = crypto.createDecipheriv;
const randomBytes = crypto.randomBytes;

let passSecret = "YR4MRnCWhBEqwMCgEu7mDcWzu4FMUQkv";

const encrypt = async (password) => {
    if (!passSecret) {
        throw new Error("Invalid password secret key. A secret key is required to encrypt passwords in the database. Please define a secret key in your .env file using PASSWORD_SECRET_KEY");
    }
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
    if (!passSecret) {
        throw new Error("Invalid password secret key. A secret key is required to encrypt passwords in the database. Please define a secret key in your .env file using PASSWORD_SECRET_KEY");
    }
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
     * @param password Password to be encrypted
     * @returns JSON object containing encrypted password & metadata
     */
    encryptPassword: async (password) => {
        const encryptedPass = await encrypt(password);
        const jsonString = JSON.stringify(JSON.stringify(encryptedPass));
        return jsonString;
    },
    /**
     * 
     * @param jsonString Stringified JSON containing encrypted password & metadata
     * @returns Decrypted password
     */
    decryptPassword: async (jsonString) => {
        const parsedJson = JSON.parse(JSON.parse(jsonString));
        return await decrypt(parsedJson);
    },
    /**
     * 
     * @param passwordAttempt The password that is being checked as a match
     * @param jsonString Stringified JSON object containing encrypted password & metadata
     */
    verifyMatch: async (passwordAttempt, jsonString) => {
        const parsedJson = JSON.parse(jsonString);
        const password = await decrypt(parsedJson);
        return password === passwordAttempt;
    }
}

const readLine = require("readline").createInterface({ input: process.stdin, output: process.stdout });

console.log(`${pkg.name} - v${pkg.version} - Author: ${pkg.author}\n`);

readLine.question("Mode (enc / dec)\n> ", (mode) => {
    if (mode === "enc") {
        readLine.question("Enter a password secret (32 bytes - 32 chars).\n> ", (secret) => {
            if (secret.length !== 32) {
                console.log("Password secret must be 32 characters (32 bytes)!");
                return readLine.close();
            }
            passSecret = secret;
            readLine.question("Enter a password you would like to be encrypted.\n> ", async (data) => {
                const jwt = await EncryptionTools.encryptPassword(data);
                console.log(`\nYour output is: ${jwt}`);
                readLine.close();
            });
        });
    } else if (mode === "dec") {
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
    } else {
        console.log("Invalid mode (must be enc / dec)");
        process.exit(1);
    }
})



readLine.on('close', () => console.log("\n Done!"));