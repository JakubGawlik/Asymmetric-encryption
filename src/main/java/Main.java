import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {

        // Alice encrypt and send this originalMessage to Bob using asymmetric encryption process (RSA algorithm).
        final String originalMessage = "Hello Bob!";

        // Generating RSA private and public keys for Alice and Bob.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair alice = keyPairGenerator.generateKeyPair();
        KeyPair bob = keyPairGenerator.generateKeyPair();

        // Can use other cipher names, like "RSA/ECB/PKCS1Padding"
        final String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        Cipher cipher = Cipher.getInstance(cipherName);

        // Alice uses Bob's public key to encrypt String and create ciphertext
        cipher.init(Cipher.ENCRYPT_MODE, bob.getPublic());

        // Storing originalMessage in byte array.
        final byte[] originalBytes = originalMessage.getBytes(StandardCharsets.UTF_8);

        // Passing the originalBytes to create byte array of encrypted cipherText
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);

        // The purpose of this Signature class is that we want to prove who sent originalMessage.
        Signature sig = Signature.getInstance("SHA256withRSA");

        // Using Alice's private key to demonstrate that she wrote it.
        sig.initSign(alice.getPrivate());

        // Updating using originalBytes to be able to verify the signature after decryption.
        sig.update(originalBytes);

        // Signature bytes are stored in byte array.
        byte[] signatureBytes = sig.sign();

        // Bob uses his private key to decrypt cipher.
        cipher.init(Cipher.DECRYPT_MODE, bob.getPrivate());

        // Storing decrypted bytes in byte array.
        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);

        // Passing decrypted bytes to String constructor.
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Displaying originalMessage, cipherText and decryptedMessage
        System.out.println("Original:\t" + originalMessage);
        System.out.println("Encrypted:\t" + Util.bytesToHex(cipherTextBytes));
        System.out.println("Decrypted:\t" + decryptedMessage);

        if (!decryptedMessage.equals(originalMessage)) {
            throw new IllegalArgumentException("Encrypted and decrypted text do not match");
        }

        System.out.println("Checking signature...");

        // Verifying signature using Alice's public key.
        sig.initVerify(alice.getPublic());
        sig.update(decryptedBytes);
        final boolean signatureValid = sig.verify(signatureBytes);
        if (signatureValid) {
            System.out.println("Yes, Alice wrote this.");
        } else {
            throw new IllegalArgumentException("Signature does not match");
        }
    }
}
