import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.AEADBadTagException;
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
        IOException exception = assertThrows(IOException.class, () -> FileEncryptor.decryptFile(
                encryptedFile.toString(),
                decryptedFile.toString(),
                WRONG_PASSWORD
        ));

        // Verify the exception chain and messages
        assertEquals("Decryption failed", exception.getMessage());
        assertInstanceOf(AEADBadTagException.class, exception.getCause());
        assertEquals("Tag mismatch", exception.getCause().getMessage());
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

        // Check that the top-level exception has the expected message
        assertEquals("Encryption failed", exception.getMessage());

        // Check that the cause is FileNotFoundException with the expected message
        assertInstanceOf(FileNotFoundException.class, exception.getCause());
        assertTrue(exception.getCause().getMessage().contains("No such file or directory"));
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

    @Test
    @DisplayName("Test getValidFilePath with existing file")
    void testGetValidFilePathExisting() {
        // Create a mock Scanner that will return our test file path
        String input = inputFile.toString() + "\n";
        Scanner mockScanner = new Scanner(new ByteArrayInputStream(input.getBytes()));

        // Test the method with shouldExist=true
        String result = FileEncryptor.getValidFilePath(mockScanner, true);
        assertEquals(inputFile.toString(), result);
    }

    @Test
    @DisplayName("Test getValidFilePath with non-existing file when checking existence")
    void testGetValidFilePathNonExistingWithCheck() {
        // Create a mock Scanner that will first return invalid path, then valid path
        String nonExistentPath = tempDir.resolve("nonexistent.txt").toString();
        String input = nonExistentPath + "\n" + inputFile.toString() + "\n";
        Scanner mockScanner = new Scanner(new ByteArrayInputStream(input.getBytes()));

        // Test the method with shouldExist=true
        String result = FileEncryptor.getValidFilePath(mockScanner, true);
        assertEquals(inputFile.toString(), result);
    }

    @Test
    @DisplayName("Test getValidFilePath with non-existing file for output")
    void testGetValidFilePathForOutput() {
        // Create a mock Scanner that will return a valid output path
        String outputPath = tempDir.resolve("newfile.txt").toString();
        String input = outputPath + "\n";
        Scanner mockScanner = new Scanner(new ByteArrayInputStream(input.getBytes()));

        // Test the method with shouldExist=false
        String result = FileEncryptor.getValidFilePath(mockScanner, false);
        assertEquals(outputPath, result);
    }

    @Test
    @DisplayName("Test getValidFilePath with invalid directory")
    void testGetValidFilePathInvalidDirectory() {
        // Create a mock Scanner that will first return invalid directory, then valid path
        String invalidPath = tempDir.resolve("nonexistent/file.txt").toString();
        String validPath = tempDir.resolve("valid.txt").toString();
        String input = invalidPath + "\n" + validPath + "\n";
        Scanner mockScanner = new Scanner(new ByteArrayInputStream(input.getBytes()));

        // Test the method with shouldExist=false
        String result = FileEncryptor.getValidFilePath(mockScanner, false);
        assertEquals(validPath, result);
    }

    @Test
    @DisplayName("Test main method with encryption flow")
    void testMainMethodEncryption() throws Exception {
        // Use a smaller test content
        String smallContent = "Small test content";
        Files.write(inputFile, smallContent.getBytes());

        // Enable silent mode and set test mode property
        FileEncryptor.setSilentMode(true);
        System.setProperty("test.mode", "true");

        // Prepare minimal input
        String input = String.format("encrypt\n%s\n%s\n%s\n",
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD);

        // Redirect System.in
        InputStream originalIn = System.in;
        try {
            System.setIn(new ByteArrayInputStream(input.getBytes()));
            FileEncryptor.main(new String[]{});

            // Verify only essential assertions
            assertTrue(Files.exists(encryptedFile));
            assertTrue(Files.size(encryptedFile) > 0);
        } finally {
            System.setIn(originalIn);
            System.clearProperty("test.mode");
            FileEncryptor.setSilentMode(false);
        }
    }

    @Test
    @DisplayName("Test main method with invalid mode then encryption")
    void testMainMethodInvalidMode() throws Exception {
        // Enable silent mode
        FileEncryptor.setSilentMode(true);

        // Prepare input with invalid mode first, then valid input
        String input = String.format("invalid\nencrypt\n%s\n%s\n%s\n",
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD);

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;

        try {
            // Redirect output to capture invalid mode message
            System.setOut(new PrintStream(outContent));

            // Use mainWithScanner directly
            Scanner scanner = new Scanner(new ByteArrayInputStream(input.getBytes()));
            FileEncryptor.mainWithScanner(scanner);

            // Verify file was created despite invalid initial mode
            assertTrue(Files.exists(encryptedFile));
            assertTrue(Files.size(encryptedFile) > 0);
        } finally {
            System.setOut(originalOut);
            FileEncryptor.setSilentMode(false);
        }
    }

    @Test
    @DisplayName("Test main method with decryption and wrong password")
    void testMainMethodDecryptionWrongPassword() throws Exception {
        // First encrypt a file
        FileEncryptor.encryptFile(
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD
        );

        // Enable silent mode
        FileEncryptor.setSilentMode(true);

        // Prepare input for decryption with wrong password
        String input = String.format("decrypt\n%s\n%s\n%s\n",
                encryptedFile.toString(),
                decryptedFile.toString(),
                WRONG_PASSWORD);

        // Redirect System.err to capture error output
        PrintStream originalErr = System.err;
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(errContent));

            // Use mainWithScanner directly instead of main
            Scanner scanner = new Scanner(new ByteArrayInputStream(input.getBytes()));
            FileEncryptor.mainWithScanner(scanner);

            assertTrue(errContent.toString().contains("Decryption failed"));
        } finally {
            System.setErr(originalErr);
            FileEncryptor.setSilentMode(false);
        }
    }

    @Test
    @DisplayName("Test corrupted encrypted file")
    void testCorruptedEncryptedFile() throws Exception {
        // First encrypt a file
        FileEncryptor.encryptFile(
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD
        );

        // Corrupt the file by modifying bytes at the end where padding is located
        byte[] fileContent = Files.readAllBytes(encryptedFile);
        // Modify the last block (last 16 bytes since AES uses 16-byte blocks)
        for (int i = fileContent.length - 16; i < fileContent.length; i++) {
            fileContent[i] ^= (byte) 0xFF; // Flip all bits in the last block
        }
        Files.write(encryptedFile, fileContent);

        // Try to decrypt the corrupted file
        IOException exception = assertThrows(IOException.class, () ->
                FileEncryptor.decryptFile(
                        encryptedFile.toString(),
                        decryptedFile.toString(),
                        TEST_PASSWORD
                )
        );

        // Verify the exception chain and messages
        assertEquals("Decryption failed", exception.getMessage());
        assertInstanceOf(AEADBadTagException.class, exception.getCause());
        assertEquals("Tag mismatch", exception.getCause().getMessage());
    }

    @Test
    @DisplayName("Test decryption with truncated salt")
    void testDecryptionWithTruncatedSalt() throws Exception {
        // First encrypt a file
        FileEncryptor.encryptFile(
                inputFile.toString(),
                encryptedFile.toString(),
                TEST_PASSWORD
        );

        // Truncate the file to have incomplete salt
        byte[] fileContent = Files.readAllBytes(encryptedFile);
        Files.write(encryptedFile, Arrays.copyOf(fileContent, FileEncryptor.SALT_SIZE - 1));

        IOException exception = assertThrows(IOException.class, () ->
                FileEncryptor.decryptFile(
                        encryptedFile.toString(),
                        decryptedFile.toString(),
                        TEST_PASSWORD
                )
        );

        // Verify top-level exception message
        assertEquals("Decryption failed", exception.getMessage());

        // Verify the cause's message
        assertNotNull(exception.getCause());
        assertInstanceOf(IOException.class, exception.getCause());
        assertEquals("Could not read the complete salt from the encrypted file", exception.getCause().getMessage());
    }
}