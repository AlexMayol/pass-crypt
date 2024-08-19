async function generateKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );

    return key;
}

export async function encrypt(data: string, password: string): Promise<string> {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16)); // 16 bytes salt
    const iv = crypto.getRandomValues(new Uint8Array(12));   // 12 bytes IV for AES-GCM

    const key = await generateKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encoder.encode(data)
    );

    const encryptedData = new Uint8Array(encrypted);
    const combinedData = new Uint8Array(salt.length + iv.length + encryptedData.length);
    combinedData.set(salt);
    combinedData.set(iv, salt.length);
    combinedData.set(encryptedData, salt.length + iv.length);

    return btoa(String.fromCharCode(...combinedData));
}

export async function decrypt(encryptedData: string, password: string): Promise<string> {
    const combinedData = new Uint8Array(
        atob(encryptedData).split("").map(char => char.charCodeAt(0))
    );

    const salt = combinedData.slice(0, 16);  // 16 bytes salt
    const iv = combinedData.slice(16, 28);   // 12 bytes IV for AES-GCM
    const data = combinedData.slice(28);

    const key = await generateKey(password, salt);

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        data
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}
