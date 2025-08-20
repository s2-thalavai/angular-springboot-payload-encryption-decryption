# angular-springboot-payload-encryption-decryption

Request Reponse Payload Encryption and Decryption using Angular and Spring Boot

production-grade flow using AES-GCM for bulk encryption and RSA-OAEP for key wrapping, 
tailored for large request/response payloads.

## High-Level Architecture
          
          Step	 Angular (Frontend)	                            Spring Boot (Backend)
          
          1      Generate AES key + IV	                        —
          2      Encrypt payload with AES-GCM	                  —
          3	     Encrypt AES key with backend's 
                 RSA public key	                                —
          4	     Send { encryptedKey, iv, authTag, 
                 encryptedPayload }	                            Receive and decrypt AES key with RSA private key
          5	     —	                                            Decrypt payload with AES-GCM
          6	     Backend responds with similarly 
                  encrypted payload	                            Angular decrypts using same flow in reverse

        
## Angular Side (Request Encryption)

typescript

async function encryptPayload(payload: object, backendPublicKeyPem: string) {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedPayload = new TextEncoder().encode(JSON.stringify(payload));
  const encryptedPayload = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encodedPayload
  );

  const backendPublicKey = await importRSAPublicKey(backendPublicKeyPem);
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
  const encryptedKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    backendPublicKey,
    rawAesKey
  );

  return {
    encryptedKey: arrayBufferToBase64(encryptedKey),
    iv: arrayBufferToBase64(iv),
    payload: arrayBufferToBase64(encryptedPayload)
  };
}

You can wrap this into an Angular service and inject it into your HTTP interceptor for automatic encryption.

## Spring Boot Side (Request Decryption)

java

// Decrypt AES key
Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedKey));

// Decrypt payload
SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
aesCipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
byte[] decryptedPayload = aesCipher.doFinal(Base64.getDecoder().decode(payload));
Modularize this into a CryptoService and wire it into a @ControllerAdvice or @RequestBodyAdvice for automatic decryption.

## Response Encryption (Spring Boot → Angular)

Same flow in reverse:

    Spring Boot encrypts response payload with AES-GCM
    
    Wraps AES key with frontend’s RSA public key
    
    Angular decrypts using its RSA private key + AES-GCM
