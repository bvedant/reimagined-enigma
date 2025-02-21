import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import javax.crypto.BadPaddingException;

class FileEncryptorTest {
    private static final String TEST_PASSWORD = "testPassword123";
    private static final String WRONG_PASSWORD = "wrongPassword123";
    private static final String TEST_CONTENT = "This is test content that will be encrypted and decrypted!";

    @TempDir
    Path tempDir;

    private Path inputFile;
    private Path encryptedFile;
    private Path decryptedFile;

    @BeforeEach
    void setUp() throws IOException {
        // Create test files
        inputFile = tempDir.resolve("input.txt");
        encryptedFile = tempDir.resolve("encrypted.bin");
        decryptedFile = tempDir.resolve("decrypted.txt");

        // Write test content to input file
        Files.write(inputFile, TEST_CONTENT.getBytes());
    }

    @Test
    @DisplayName("Test successful encryption and decryption")
    void testEncryptionDecryption() throws Exception {
        // Encrypt the file
        FileEncryptor.encryptFile(
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD
        );

        // Verify encrypted file exists and is different from input
        assertTrue(Files.exists(encryptedFile));
        assertFalse(Arrays.equals(
                Files.readAllBytes(inputFile),
                Files.readAllBytes(encryptedFile)
        ));

        // Decrypt the file
        FileEncryptor.decryptFile(
                encryptedFile.toString(),
                decryptedFile.toString(),
                TEST_PASSWORD
        );

        // Verify decrypted content matches original
        String decryptedContent = new String(Files.readAllBytes(decryptedFile));
        assertEquals(TEST_CONTENT, decryptedContent);
    }

    @Test
    @DisplayName("Test decryption with wrong password")
    void testDecryptionWithWrongPassword() {
        // Encrypt file first
        assertDoesNotThrow(() -> FileEncryptor.encryptFile(
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD
        ));

        // Try to decrypt with wrong password
        assertThrows(BadPaddingException.class, () -> FileEncryptor.decryptFile(
                encryptedFile.toString(),
                decryptedFile.toString(),
                WRONG_PASSWORD
        ));
    }

    @Test
    @DisplayName("Test encryption with non-existent input file")
    void testEncryptionWithNonExistentInput() {
        String nonExistentFile = tempDir.resolve("doesnotexist.txt").toString();

        IOException exception = assertThrows(IOException.class, () ->
                FileEncryptor.encryptFile(
                        nonExistentFile,
                        encryptedFile.toString(),
                        TEST_PASSWORD
                )
        );

        assertTrue(exception.getMessage().contains("No such file"));
    }

    @Test
    @DisplayName("Test encryption with invalid output path")
    void testEncryptionWithInvalidOutput() {
        String invalidOutput = tempDir.resolve("nonexistent/encrypted.bin").toString();

        assertThrows(IOException.class, () ->
                FileEncryptor.encryptFile(
                        inputFile.toString(),
                        invalidOutput,
                        TEST_PASSWORD
                )
        );
    }

    @Test
    @DisplayName("Test encryption and decryption of empty file")
    void testEncryptionDecryptionOfEmptyFile() throws Exception {
        // Create empty file
        Path emptyFile = tempDir.resolve("empty.txt");
        Files.createFile(emptyFile);

        Path encryptedEmpty = tempDir.resolve("empty.encrypted");
        Path decryptedEmpty = tempDir.resolve("empty.decrypted");

        // Encrypt and decrypt empty file
        FileEncryptor.encryptFile(
                emptyFile.toString(),
                encryptedEmpty.toString(),
                TEST_PASSWORD
        );

        FileEncryptor.decryptFile(
                encryptedEmpty.toString(),
                decryptedEmpty.toString(),
                TEST_PASSWORD
        );

        // Verify decrypted file is also empty
        assertEquals(0, Files.size(decryptedEmpty));
    }

    @Test
    @DisplayName("Test encryption and decryption of large file")
    void testEncryptionDecryptionOfLargeFile() throws Exception {
        // Create a larger file (5MB)
        Path largeFile = tempDir.resolve("large.txt");
        Path encryptedLarge = tempDir.resolve("large.encrypted");
        Path decryptedLarge = tempDir.resolve("large.decrypted");

        byte[] largeContent = new byte[5 * 1024 * 1024]; // 5MB
        new java.security.SecureRandom().nextBytes(largeContent);
        Files.write(largeFile, largeContent);

        // Encrypt and decrypt
        FileEncryptor.encryptFile(
                largeFile.toString(),
                encryptedLarge.toString(),
                TEST_PASSWORD
        );

        FileEncryptor.decryptFile(
                encryptedLarge.toString(),
                decryptedLarge.toString(),
                TEST_PASSWORD
        );

        // Verify content matches
        assertArrayEquals(
                Files.readAllBytes(largeFile),
                Files.readAllBytes(decryptedLarge)
        );
    }
}