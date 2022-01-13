Alice encrypt and send this originalMessage to Bob using asymmetric encryption process (RSA 

1. Generating RSA private and public keys for Alice and 

2. Alice uses Bob's public key to encrypt String and create ciphertext

3. Storing originalMessage in byte array.

4. Passing the originalBytes to create byte array of encrypted cipherText

5. The purpose of this Signature class is that we want to prove who sent originalMessage.

6. Using Alice's private key to demonstrate that she wrote it.

7. Updating using originalBytes to be able to verify the signature after decryption.

8. Signature bytes are stored in byte array.

9. Bob uses his private key to decrypt cipher.

10. Storing decrypted bytes in byte array.

11. Passing decrypted bytes to String constructor.

12. Displaying originalMessage, cipherText and decryptedMessage

13. Verifying signature using Alice's public key.


