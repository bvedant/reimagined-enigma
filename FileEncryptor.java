import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileEncryptor {
    private static final Logger LOGGER = Logger.getLogger(FileEncryptor.class.getName());
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 65536;

    // Salt size for additional security
    private static final int SALT_SIZE = 32;

    /**
     * Generates a secure AES key from a password using PBKDF2
     */
    private static SecretKey generateKey(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * Encrypts a file using AES encryption
     */
    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);

        // Generate the encryption key
        SecretKey key = generateKey(password, salt);

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Write the salt at the beginning of the output file
            fos.write(salt);

            // Read the input file and encrypt it
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                if (encryptedBytes != null) {
                    fos.write(encryptedBytes);
                }
            }

            // Write the final block
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                fos.write(finalBytes);
            }
        }
    }

    /**
     * Decrypts a file that was encrypted using AES encryption
     */
    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            // Read the salt from the beginning of the file
            byte[] salt = new byte[SALT_SIZE];
            int saltBytesRead;
            int offset = 0;
            while (offset < SALT_SIZE && (saltBytesRead = fis.read(salt, offset, SALT_SIZE - offset)) != -1) {
                offset += saltBytesRead;
            }

            if (offset < SALT_SIZE) {
                throw new IOException("Could not read the complete salt from the encrypted file");
            }

            // Generate the decryption key
            SecretKey key = generateKey(password, salt);

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);

            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
                    if (decryptedBytes != null) {
                        fos.write(decryptedBytes);
                    }
                }

                // Write the final block
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null) {
                    fos.write(finalBytes);
                }
            }
        }
    }


    public static void main(String[] args) {
        try {
            if (args.length != 4) {
                System.out.println("Usage: java FileEncryptor [encrypt/decrypt] [input file] [output file] [password]");
                return;
            }

            String mode = args[0].toLowerCase();
            String inputFile = args[1];
            String outputFile = args[2];
            String password = args[3];

            switch (mode) {
                case "encrypt":
                    encryptFile(inputFile, outputFile, password);
                    System.out.println("File encrypted successfully!");
                    break;
                case "decrypt":
                    decryptFile(inputFile, outputFile, password);
                    System.out.println("File decrypted successfully!");
                    break;
                default:
                    System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during file encryption/decryption", e);
            System.err.println("Error: " + e.getMessage());
        }
    }
}
