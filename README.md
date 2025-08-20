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
          
