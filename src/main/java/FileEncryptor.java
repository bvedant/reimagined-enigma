import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileEncryptor {
    private static final Logger LOGGER = Logger.getLogger(FileEncryptor.class.getName());
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 65536;
    static final int SALT_SIZE = 32;

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
    public static void decryptFile(String inputFile, String outputFile, String password)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
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
            SecretKey key;
            try {
                key = generateKey(password, salt);
            } catch (Exception e) {
                throw new InvalidKeyException("Failed to generate key from password", e);
            }

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

    /**
     * Gets and validates file path from user input
     */
    static String getValidFilePath(Scanner scanner, String prompt, boolean shouldExist) {
        while (true) {
            System.out.print(prompt);
            String filePath = scanner.nextLine().trim();
            File file = new File(filePath);

            if (shouldExist) {
                if (!file.exists()) {
                    System.out.println("Error: File does not exist. Please enter a valid file path.");
                    continue;
                }
                if (!file.canRead()) {
                    System.out.println("Error: Cannot read file. Please check permissions.");
                    continue;
                }
            } else {
                File parentDir = file.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    System.out.println("Error: Directory does not exist. Please enter a valid file path.");
                    continue;
                }
                if (parentDir != null && !parentDir.canWrite()) {
                    System.out.println("Error: Cannot write to directory. Please check permissions.");
                    continue;
                }
            }

            return filePath;
        }
    }

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {
            // Get operation mode
            String mode;
            while (true) {
                System.out.print("Enter mode (encrypt/decrypt): ");
                mode = scanner.nextLine().toLowerCase().trim();
                if (mode.equals("encrypt") || mode.equals("decrypt")) {
                    break;
                }
                System.out.println("Invalid mode. Please enter 'encrypt' or 'decrypt'.");
            }

            // Get input file path
            String inputFile = getValidFilePath(scanner, "Enter input file path: ", true);

            // Get output file path
            String outputFile = getValidFilePath(scanner, "Enter output file path: ", false);

            // Get password
            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            // Perform the requested operation
            switch (mode) {
                case "encrypt":
                    encryptFile(inputFile, outputFile, password);
                    System.out.println("File encrypted successfully!");
                    break;
                case "decrypt":
                    try {
                        decryptFile(inputFile, outputFile, password);
                        System.out.println("File decrypted successfully!");
                    } catch (BadPaddingException e) {
                        LOGGER.log(Level.WARNING, "Decryption failed - likely incorrect password", e);
                        System.err.println("Error: Incorrect password or corrupted file");
                    }
                    break;
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "File I/O error", e);
            System.err.println("Error: " + e.getMessage());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during file encryption/decryption", e);
            System.err.println("Error: " + e.getMessage());
        }
    }
}
