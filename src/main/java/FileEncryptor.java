import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class FileEncryptor {
    private static final Logger LOGGER = Logger.getLogger(FileEncryptor.class.getName());
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 65536;
    public static final int SALT_SIZE = 32;  // Made public for testing
    private static final int VERSION = 1;
    private static final long MAX_FILE_SIZE = 1L << 30; // 1GB limit

    // Add silent mode flag
    private static boolean silentMode = false;

    // Add setter for silent mode
    public static void setSilentMode(boolean silent) {
        silentMode = silent;
    }

    // Prevent instantiation
    private FileEncryptor() {
        throw new AssertionError("This class should not be instantiated");
    }

    private static SecretKey generateKey(char[] password, byte[] salt) throws Exception {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            // Clear sensitive data
            Arrays.fill(password, '\0');
        }
    }

    public static void encryptFile(String inputPath, String outputPath, String password)
            throws IOException {

        validateInputs(inputPath, outputPath, password);

        File inputFile = new File(inputPath);
        if (inputFile.length() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File too large: " + inputFile.length() + " bytes");
        }

        char[] passwordChars = password.toCharArray();
        try {
            // Generate salt and IV
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_SIZE];
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(salt);
            random.nextBytes(iv);

            // Generate key and initialize cipher
            SecretKey key = generateKey(passwordChars, salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            try (FileInputStream fis = new FileInputStream(inputFile);
                 FileOutputStream fos = new FileOutputStream(outputPath)) {

                // Write header
                fos.write(VERSION);
                fos.write(salt);
                fos.write(iv);

                // Process file in chunks
                byte[] buffer = new byte[8192];
                long totalBytes = 0;
                int bytesRead;

                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                    if (encryptedBytes != null) {
                        fos.write(encryptedBytes);
                    }
                    totalBytes += bytesRead;
                    updateProgress(totalBytes, inputFile.length());
                }

                // Write final block
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null) {
                    fos.write(finalBytes);
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Encryption failed", e);
            throw new IOException("Encryption failed", e);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    public static void decryptFile(String inputPath, String outputPath, String password)
            throws IOException {

        validateInputs(inputPath, outputPath, password);
        char[] passwordChars = password.toCharArray();

        try (FileInputStream fis = new FileInputStream(inputPath)) {
            // Read header
            int version = fis.read();
            if (version != VERSION) {
                throw new IOException("Unsupported version: " + version);
            }

            byte[] salt = new byte[SALT_SIZE];
            byte[] iv = new byte[GCM_IV_LENGTH];
            readFully(fis, salt);
            readFully(fis, iv);

            // Initialize cipher
            SecretKey key = generateKey(passwordChars, salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
                    if (decryptedBytes != null) {
                        fos.write(decryptedBytes);
                    }
                }

                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null) {
                    fos.write(finalBytes);
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Decryption failed", e);
            throw new IOException("Decryption failed", e);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    static void validateInputs(String inputPath, String outputPath, String password) {
        if (inputPath == null || outputPath == null || password == null) {
            throw new IllegalArgumentException("Null arguments not allowed");
        }
        if (password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        if (inputPath.equals(outputPath)) {
            throw new IllegalArgumentException("Input and output paths must be different");
        }
    }

    private static void readFully(InputStream is, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = is.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                throw new IOException("Could not read the complete salt from the encrypted file");
            }
            offset += read;
        }
    }

    /**
     * Gets and validates file path from user input
     */
    static String getValidFilePath(Scanner scanner, boolean shouldExist) {
        while (true) {
            System.out.print("Test prompt: ");
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

    private static void updateProgress(long current, long total) {
        // Skip progress updates in silent mode
        if (silentMode) {
            return;
        }

        int percent = (int) (current * 100 / total);
        System.out.printf("\rProgress: %d%%", percent);
        if (current == total) {
            System.out.println();
        }
    }

    public static void main(String[] args) {
        // For testing purposes, check if running in test mode
        if (System.getProperty("test.mode") != null) {
            setSilentMode(true);
            // Use Scanner instead of Console in test mode
            mainWithScanner(new Scanner(System.in));
            return;
        }

        Console console = System.console();
        if (console == null) {
            System.err.println("Console not available. Please run from a terminal.");
            System.exit(1);
        }

        try {
            // Get operation mode
            String mode;
            while (true) {
                mode = console.readLine("Enter mode (encrypt/decrypt): ").toLowerCase().trim();
                if (mode.equals("encrypt") || mode.equals("decrypt")) {
                    break;
                }
                System.out.println("Invalid mode. Please enter 'encrypt' or 'decrypt'.");
            }

            // Get file paths
            String inputFile = console.readLine("Enter input file path: ").trim();
            String outputFile = console.readLine("Enter output file path: ").trim();

            // Get password securely (characters won't be displayed)
            char[] password = console.readPassword("Enter password: ");
            if (password == null || password.length < 8) {
                System.err.println("Password must be at least 8 characters long.");
                return;
            }

            // Perform the requested operation
            if (mode.equals("encrypt")) {
                encryptFile(inputFile, outputFile, new String(password));
                System.out.println("File encrypted successfully!");
            } else {
                decryptFile(inputFile, outputFile, new String(password));
                System.out.println("File decrypted successfully!");
            }

        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            LOGGER.log(Level.SEVERE, "File I/O error", e);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            LOGGER.log(Level.SEVERE, "Operation failed", e);
        }
    }

    // Add helper method for testing
    static void mainWithScanner(Scanner scanner) {
        try {
            // Get operation mode
            String mode;
            do {
                mode = scanner.nextLine().toLowerCase().trim();
            } while (!mode.equals("encrypt") && !mode.equals("decrypt"));

            // Get file paths and password
            String inputFile = scanner.nextLine().trim();
            String outputFile = scanner.nextLine().trim();
            String password = scanner.nextLine().trim();

            if (password.length() < 8) {
                System.err.println("Password must be at least 8 characters long.");
                return;
            }

            // Perform the requested operation
            if (mode.equals("encrypt")) {
                encryptFile(inputFile, outputFile, password);
            } else {
                decryptFile(inputFile, outputFile, password);
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            LOGGER.log(Level.SEVERE, "Operation failed", e);
        }
    }
}
