/**
 * SIMPLE XOR ENCRYPTION/DECRYPTION SYSTEM
 * A beginner-friendly project to understand basic cryptography
 * Perfect for password verification systems
 * Author: [Your Name]
 * GitHub: [Your Repo Link]
 */
import java.util.Base64;
import java.util.Scanner;

public class SimpleXORCryptography {
    
    // ============================================
    // CORE ENCRYPTION/DECRYPTION METHODS
    // ============================================
    
    /**
     * Encrypt text using XOR cipher with a key
     * XOR principle: (data ^ key) ^ key = data
     * @param plainText The text to encrypt
     * @param key The encryption key (can be any string)
     * @return Base64 encoded encrypted string
     */
    public static String encrypt(String plainText, String key) {
        if (plainText == null || key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Text and key cannot be null/empty");
        }
        
        // Convert to byte arrays
        byte[] textBytes = plainText.getBytes();
        byte[] keyBytes = key.getBytes();
        byte[] encryptedBytes = new byte[textBytes.length];
        
        // XOR each byte with key bytes (cycling through key)
        for (int i = 0; i < textBytes.length; i++) {
            encryptedBytes[i] = (byte)(textBytes[i] ^ keyBytes[i % keyBytes.length]);
        }
        
        // Encode to Base64 for safe string representation
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    /**
     * Decrypt Base64 encoded text using XOR cipher
     * @param encryptedText Base64 encoded encrypted text
     * @param key The same key used for encryption
     * @return Decrypted plain text
     */
    public static String decrypt(String encryptedText, String key) {
        if (encryptedText == null || key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Encrypted text and key cannot be null/empty");
        }
        
        try {
            // Decode from Base64
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] keyBytes = key.getBytes();
            byte[] decryptedBytes = new byte[encryptedBytes.length];
            
            // XOR each byte with key bytes (same operation as encryption!)
            for (int i = 0; i < encryptedBytes.length; i++) {
                decryptedBytes[i] = (byte)(encryptedBytes[i] ^ keyBytes[i % keyBytes.length]);
            }
            
            return new String(decryptedBytes);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 encoded string");
        }
    }
    
    // ============================================
    // PASSWORD VERIFICATION SYSTEM WITH ENCRYPTION
    // ============================================
    
    /**
     * User credentials storage with encrypted passwords
     * Simulates a simple user database
     */
    static class UserDatabase {
        // In a real system, this would be in a database
        // For demo, we'll use a simple map
        private java.util.Map<String, String> encryptedPasswords = new java.util.HashMap<>();
        private static final String MASTER_KEY = "mySecretKey123!"; // Should be stored securely
        
        /**
         * Register a new user with encrypted password
         */
        public boolean registerUser(String username, String password) {
            if (username == null || username.isEmpty() || 
                password == null || password.isEmpty()) {
                System.out.println(" Username and password cannot be empty");
                return false;
            }
            
            if (encryptedPasswords.containsKey(username)) {
                System.out.println(" Username already exists");
                return false;
            }
            
            // Encrypt the password before storing
            String encryptedPassword = encrypt(password, MASTER_KEY);
            encryptedPasswords.put(username, encryptedPassword);
            
            System.out.println(" User '" + username + "' registered successfully!");
            System.out.println("   Stored (encrypted): " + encryptedPassword.substring(0, Math.min(20, encryptedPassword.length())) + "...");
            return true;
        }
        
        /**
         * Verify user login with encrypted password comparison
         */
        public boolean verifyLogin(String username, String password) {
            if (!encryptedPasswords.containsKey(username)) {
                System.out.println(" User not found");
                return false;
            }
            
            // Encrypt the provided password with same key
            String encryptedAttempt = encrypt(password, MASTER_KEY);
            String storedEncrypted = encryptedPasswords.get(username);
            
            // Compare encrypted versions (NOT plain text!)
            boolean verified = storedEncrypted.equals(encryptedAttempt);
            
            if (verified) {
                System.out.println(" Login successful for user: " + username);
            } else {
                System.out.println(" Invalid password for user: " + username);
            }
            
            return verified;
        }
        
        /**
         * Display all users (for demo purposes - never do this in production!)
         */
        public void displayUsers() {
            System.out.println("\n=== REGISTERED USERS (ENCRYPTED PASSWORDS) ===");
            if (encryptedPasswords.isEmpty()) {
                System.out.println("No users registered");
                return;
            }
            
            for (String username : encryptedPasswords.keySet()) {
                String encrypted = encryptedPasswords.get(username);
                System.out.println("User: " + username);
                System.out.println("  Encrypted Password: " + encrypted);
                System.out.println("  Password Length: " + encrypted.length() + " chars");
                System.out.println();
            }
        }
    }
    
    // ============================================
    // FILE ENCRYPTION UTILITY
    // ============================================
    
    /**
     * Simple file encryption/decryption utility
     * Demonstrates XOR encryption on files
     */
    static class FileEncryptor {
        
        /**
         * Encrypt a text file using XOR cipher
         */
        public static boolean encryptFile(String inputFile, String outputFile, String key) {
            try {
                java.nio.file.Path inputPath = java.nio.file.Paths.get(inputFile);
                byte[] fileBytes = java.nio.file.Files.readAllBytes(inputPath);
                byte[] keyBytes = key.getBytes();
                
                // XOR each byte
                for (int i = 0; i < fileBytes.length; i++) {
                    fileBytes[i] ^= keyBytes[i % keyBytes.length];
                }
                
                // Write encrypted bytes
                java.nio.file.Files.write(java.nio.file.Paths.get(outputFile), fileBytes);
                System.out.println(" File encrypted successfully: " + outputFile);
                return true;
                
            } catch (java.io.IOException e) {
                System.out.println(" Error encrypting file: " + e.getMessage());
                return false;
            }
        }
        
        /**
         * Decrypt a file (same as encryption - XOR is symmetric!)
         */
        public static boolean decryptFile(String inputFile, String outputFile, String key) {
            // Decryption is identical to encryption with XOR!
            return encryptFile(inputFile, outputFile, key);
        }
    }
    
    // ============================================
    // INTERACTIVE DEMONSTRATION
    // ============================================
    
    /**
     * Interactive console interface
     */
    public static void interactiveDemo() {
        Scanner scanner = new Scanner(System.in);
        UserDatabase userDB = new UserDatabase();
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("        XOR ENCRYPTION/DECRYPTION SYSTEM");
        System.out.println("=".repeat(60));
        
        boolean running = true;
        
        while (running) {
            System.out.println("\n=== MAIN MENU ===");
            System.out.println("1. Text Encryption/Decryption Demo");
            System.out.println("2. User Registration & Login (Password Verification)");
            System.out.println("3. File Encryption Demo");
            System.out.println("4. How XOR Encryption Works");
            System.out.println("5. View Registered Users (Encrypted)");
            System.out.println("6. Exit");
            System.out.print("\nEnter choice (1-6): ");
            
            try {
                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline
                
                switch (choice) {
                    case 1:
                        textEncryptionDemo(scanner);
                        break;
                    case 2:
                        userRegistrationDemo(scanner, userDB);
                        break;
                    case 3:
                        fileEncryptionDemo(scanner);
                        break;
                    case 4:
                        explainXOREncryption();
                        break;
                    case 5:
                        userDB.displayUsers();
                        break;
                    case 6:
                        running = false;
                        System.out.println("\n Thank you for exploring XOR Cryptography!");
                        break;
                    default:
                        System.out.println(" Invalid choice. Please enter 1-6.");
                }
                
            } catch (Exception e) {
                System.out.println(" Invalid input. Please enter a number.");
                scanner.nextLine(); // Clear invalid input
            }
        }
        
        scanner.close();
    }
    
    private static void textEncryptionDemo(Scanner scanner) {
        System.out.println("\n=== TEXT ENCRYPTION/DECRYPTION ===");
        System.out.print("Enter text to encrypt: ");
        String text = scanner.nextLine();
        
        System.out.print("Enter encryption key: ");
        String key = scanner.nextLine();
        
        try {
            // Encrypt
            String encrypted = encrypt(text, key);
            System.out.println("\n ENCRYPTED (Base64): " + encrypted);
            
            // Decrypt
            String decrypted = decrypt(encrypted, key);
            System.out.println(" DECRYPTED: " + decrypted);
            
            // Verify
            if (text.equals(decrypted)) {
                System.out.println(" Verification: Original == Decrypted ");
            } else {
                System.out.println(" Verification failed!");
            }
            
        } catch (Exception e) {
            System.out.println(" Error: " + e.getMessage());
        }
    }
    
    private static void userRegistrationDemo(Scanner scanner, UserDatabase userDB) {
        System.out.println("\n=== USER REGISTRATION & LOGIN ===");
        System.out.println("1. Register New User");
        System.out.println("2. Login");
        System.out.print("Enter choice (1-2): ");
        
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline
        
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        if (choice == 1) {
            userDB.registerUser(username, password);
        } else if (choice == 2) {
            userDB.verifyLogin(username, password);
        } else {
            System.out.println(" Invalid choice");
        }
    }
    
    private static void fileEncryptionDemo(Scanner scanner) {
        System.out.println("\n=== FILE ENCRYPTION DEMO ===");
        System.out.println("Note: This will create test files in the current directory");
        
        try {
            // Create a test file
            String testContent = "This is a secret message!\nLine 2 of secret.\nLine 3 is even more secret!";
            java.nio.file.Files.write(java.nio.file.Paths.get("test_original.txt"), 
                                     testContent.getBytes());
            
            System.out.print("Enter encryption key: ");
            String key = scanner.nextLine();
            
            // Encrypt the file
            boolean success = FileEncryptor.encryptFile("test_original.txt", 
                                                       "test_encrypted.dat", key);
            
            if (success) {
                // Decrypt it back
                FileEncryptor.decryptFile("test_encrypted.dat", 
                                         "test_decrypted.txt", key);
                
                // Read and compare
                String original = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get("test_original.txt")));
                String decrypted = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get("test_decrypted.txt")));
                
                System.out.println("\n FILE COMPARISON:");
                System.out.println("Original: " + original.length() + " bytes");
                System.out.println("Decrypted: " + decrypted.length() + " bytes");
                System.out.println("Match: " + original.equals(decrypted));
                
                // Clean up (optional)
                System.out.print("\nDelete test files? (y/n): ");
                if (scanner.nextLine().equalsIgnoreCase("y")) {
                    java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get("test_original.txt"));
                    java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get("test_encrypted.dat"));
                    java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get("test_decrypted.txt"));
                    System.out.println("Test files deleted.");
                }
            }
            
        } catch (Exception e) {
            System.out.println(" Error: " + e.getMessage());
        }
    }
    
    private static void explainXOREncryption() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("              HOW XOR ENCRYPTION WORKS");
        System.out.println("=".repeat(60));
        
        System.out.println("\n XOR (Exclusive OR) OPERATOR:");
        System.out.println("    Returns 1 if bits are different");
        System.out.println("    Returns 0 if bits are the same");
        System.out.println("    Truth table: 0^0=0, 0^1=1, 1^0=1, 1^1=0");
        
        System.out.println("\n MAGIC PROPERTY OF XOR:");
        System.out.println("   If:   A ^ B = C");
        System.out.println("   Then: C ^ B = A  ← Decryption!");
        
        System.out.println("\n SIMPLE EXAMPLE:");
        System.out.println("   Plain text:  'A' (ASCII 65 = 01000001)");
        System.out.println("   Key:         'K' (ASCII 75 = 01001011)");
        System.out.println("   XOR:         01000001 ^ 01001011 = 00001010");
        System.out.println("   Encrypted:   00001010 (ASCII 10)");
        System.out.println("   Decrypt:     00001010 ^ 01001011 = 01000001 = 'A' ✓");
        
        System.out.println("\n  SECURITY NOTES:");
        System.out.println("    XOR alone is NOT secure for real encryption");
        System.out.println("    Same key reuse reveals patterns");
        System.out.println("    Short keys can be brute-forced");
        System.out.println("    Real systems use XOR as ONE component in AES, etc.");
        
        System.out.println("\n GOOD FOR LEARNING:");
        System.out.println("    Understands basic cryptography");
        System.out.println("    Demonstrates symmetric encryption");
        System.out.println("    Great for educational projects");
        System.out.println("    Perfect foundation for understanding AES");
        
        System.out.println("\n" + "=".repeat(60));
    }
    
    // ============================================
    // TESTING & VALIDATION METHODS
    // ============================================
    
    /**
     * Run automated tests to verify encryption/decryption works
     */
    public static void runTests() {
        System.out.println("\n=== RUNNING AUTOMATED TESTS ===");
        
        String[] testCases = {
            "Hello World!",
            "Password123!@#",
            "Java is awesome",
            " Unicode emoji test ",
            "",  // Empty string
            "A".repeat(100)  // Long repetitive string
        };
        
        String testKey = "SecretKey123";
        int passed = 0;
        int failed = 0;
        
        for (String original : testCases) {
            try {
                String encrypted = encrypt(original, testKey);
                String decrypted = decrypt(encrypted, testKey);
                
                if (original.equals(decrypted)) {
                    System.out.println(" PASS: \"" + 
                        (original.length() > 20 ? original.substring(0, 20) + "..." : original) + 
                        "\"");
                    passed++;
                } else {
                    System.out.println(" FAIL: \"" + original + "\"");
                    System.out.println("   Original length: " + original.length());
                    System.out.println("   Decrypted length: " + decrypted.length());
                    failed++;
                }
                
            } catch (Exception e) {
                System.out.println(" ERROR: " + e.getMessage());
                failed++;
            }
        }
        
        System.out.println("\n TEST RESULTS:");
        System.out.println("   Passed: " + passed);
        System.out.println("   Failed: " + failed);
        System.out.println("   Total:  " + (passed + failed));
        
        if (failed == 0) {
            System.out.println(" All tests passed!");
        }
    }
    
    // ============================================
    // MAIN ENTRY POINT
    // ============================================
    
    public static void main(String[] args) {
        System.out.println(" XOR CRYPTOGRAPHY PROJECT - Java Beginner Friendly");
       // System.out.println("GitHub Ready: Perfect for password-verify repository\n");
        
        if (args.length > 0 && args[0].equalsIgnoreCase("test")) {
            // Run tests if "test" argument provided
            runTests();
        } else if (args.length == 3 && args[0].equalsIgnoreCase("encrypt")) {
            // Command-line encryption: java SimpleXORCryptography encrypt "text" "key"
            try {
                String encrypted = encrypt(args[1], args[2]);
                System.out.println("Encrypted: " + encrypted);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        } else if (args.length == 3 && args[0].equalsIgnoreCase("decrypt")) {
            // Command-line decryption: java SimpleXORCryptography decrypt "encrypted" "key"
            try {
                String decrypted = decrypt(args[1], args[2]);
                System.out.println("Decrypted: " + decrypted);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        } else {
            // Interactive mode by default
            interactiveDemo();
        }
    }
}
