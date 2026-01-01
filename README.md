#  XOR Cryptography & Password Verification System

A **beginner-friendly** Java project demonstrating XOR encryption/decryption with practical applications in password verification. Perfect for learning basic cryptography concepts!

##  Prerequisites (Must have before starting)

### **Java Development Kit (JDK 17 or higher)**
- **Download**: [Eclipse Temurin JDK](https://adoptium.net/)
- **macOS**: `brew install openjdk@17`
- **Verify**: Run `java -version` in terminal

### **Visual Studio Code**
- **Download**: [VS Code](https://code.visualstudio.com/)
- **Install**: Follow platform-specific instructions

### **VS Code Java Extension**
- Open VS Code Extensions panel (`Ctrl+Shift+X` or `Cmd+Shift+X` on Mac)
- Search for **"Extension Pack for Java"** (by Microsoft)
- Click Install

##  Quick Start

### **One-File Setup** (No Maven/Gradle required!)
```bash
# 1. Download the file
wget https://raw.githubusercontent.com/daniel-oyoo/password-verify/main/SimpleXORCryptography.java

# 2. Compile (Java 8+ required)
javac SimpleXORCryptography.java

# 3. Run interactive demo
java SimpleXORCryptography
```

### **Or Clone & Run**
```bash
git clone https://github.com/daniel-oyoo/password-verify.git
cd password-verify
javac SimpleXORCryptography.java
java SimpleXORCryptography
```

##  Features

-  XOR Encryption/Decryption - Simple symmetric cryptography
-  Password Verification - Store/verify encrypted passwords
-  File Encryption - Encrypt/decrypt text files
-  Educational - Detailed XOR explanations
-  Interactive Menu - Easy-to-use console interface
-  Built-in Tests - Verify everything works

##  Demo

```
 XOR CRYPTOGRAPHY PROJECT - Java Beginner Friendly
========================================================

=== MAIN MENU ===
1. Text Encryption/Decryption Demo
2. User Registration & Login (Password Verification)
3. File Encryption Demo
4. How XOR Encryption Works
5. View Registered Users (Encrypted)
6. Exit

Enter choice (1-6): 1

=== TEXT ENCRYPTION/DECRYPTION ===
Enter text to encrypt: Hello GitHub!
Enter encryption key: secret123

 ENCRYPTED (Base64): Mz4EBAcXEFs=
 DECRYPTED: Hello GitHub!
 Verification: Original == Decrypted 
```

##  How XOR Encryption Works

XOR (Exclusive OR) has a magical property that makes it perfect for simple encryption:

```java
// XOR Magic:
// If:   plaintext ^ key = encrypted
// Then: encrypted ^ key = plaintext  ← Same operation decrypts!

// Example with bits:
// Plain:  H = 01001000
// Key:    s = 01110011
// XOR:      00111011 = encrypted
// XOR again:00111011 ^ 01110011 = 01001000 = H ✓
```

##  Command Line Usage

### **Run Tests**
```bash
java SimpleXORCryptography test
```

### **Quick Encrypt**
```bash
java SimpleXORCryptography encrypt "My Secret" "password123"
# Output: Base64 encoded encrypted string
```

### **Quick Decrypt**
```bash
java SimpleXORCryptography decrypt "Mz4EBAcXEFs=" "password123"
# Output: Decrypted plain text
```

### **Interactive Mode** (Default)
```bash
java SimpleXORCryptography
# Launches the interactive menu system
```

## 🔧 Code Examples

### **Basic Usage**
```java
import java.util.Base64;

public class Example {
    public static void main(String[] args) {
        String message = "My password";
        String key = "MySecretKey123";
        
        // Encrypt
        String encrypted = SimpleXORCryptography.encrypt(message, key);
        System.out.println("Encrypted: " + encrypted);
        
        // Decrypt
        String decrypted = SimpleXORCryptography.decrypt(encrypted, key);
        System.out.println("Decrypted: " + decrypted);
    }
}
```

### **Password Verification**
```java
// Create user database
SimpleXORCryptography.UserDatabase db = new SimpleXORCryptography.UserDatabase();

// Register user (password encrypted automatically)
db.registerUser("alice", "securePass123!");

// Verify login (compares encrypted versions)
boolean success = db.verifyLogin("alice", "securePass123!");
```

### **File Encryption**
```java
// Encrypt a file
SimpleXORCryptography.FileEncryptor.encryptFile(
    "secret.txt", 
    "encrypted.dat", 
    "MyKey"
);

// Decrypt (same method!)
SimpleXORCryptography.FileEncryptor.decryptFile(
    "encrypted.dat",
    "decrypted.txt",
    "MyKey"
);
```

##  Menu Options

| Option | Description |
|--------|-------------|
| **1** | **Text Encryption** - Encrypt/decrypt any text |
| **2** | **User Registration** - Password verification demo |
| **3** | **File Encryption** - Encrypt/decrypt files |
| **4** | **Learn XOR** - Detailed explanation |
| **5** | **View Users** - See encrypted passwords |
| **6** | **Exit** | 

##  Project Structure

The entire project is in **one file** (`SimpleXORCryptography.java`) with these internal classes:

```
XORCryptography.java
├── Core Methods
│   ├── encrypt()           # XOR encryption
│   └── decrypt()           # XOR decryption
├── UserDatabase           # Password storage/verification
├── FileEncryptor          # File encryption utility
├── PerformanceOptimizations # Bitwise tricks
└── Main Menu System       # Interactive interface
```

##  Security Disclaimer

**This is for EDUCATIONAL purposes only!** Real applications use:

| This Project | Real Systems |
|-------------|-------------|
| XOR encryption | AES-256 encryption |
| Single key | Key derivation (PBKDF2) |
| No salting | Salted hashes |
| Simple XOR | Multiple encryption rounds |

**Never use this for actual password storage!** Use established libraries like:
- bcrypt
- Argon2
- PBKDF2 with HMAC-SHA256

##  Testing

Run the built-in test suite:
```bash
java SimpleXORCryptography test

# Expected output:
=== RUNNING AUTOMATED TESTS ===
 PASS: "Hello World!"
 PASS: "Password123!@#"
 PASS: "Java is awesome"
...
 All tests passed!
```

##  FAQ

### **Q: Why XOR for encryption?**
A: XOR is symmetric - the same operation encrypts AND decrypts. Perfect for learning basic cryptography concepts.

### **Q: Is this secure?**
A: **No!** This demonstrates the concept. Real encryption needs stronger algorithms, key management, and protection against attacks.

### **Q: Can I extend this project?**
A: Absolutely! Try adding:
- Password strength checker
- GUI interface
- Database storage
- Brute-force protection

### **Q: What if I get compilation errors?**
A: Ensure you have Java 8+. Check with:
```bash
java -version
```

##  Learning Resources

- [XOR Cipher Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

##  Contributing

Found a bug? Want to improve something?
1. Fork the repo
2. Create a feature branch
3. Submit a pull request

##  License

MIT License - see [LICENSE](LICENSE) file

##  Author

**Daniel Oyoo** - Java Developer  
Live by the code! 

---

<p align="center">
  Made  for Java beginners
  <br>
  <sub>Remember: Real security is complex. Learn the basics first!</sub>
</p>

##  Ready to Run?

```bash
# Just download and run!
curl -O https://raw.githubusercontent.com/daniel-oyoo/password-verify/main/SimpleXORCryptography.java
javac SimpleXORCryptography.java
java SimpleXORCryptography
```

**Start with option 4 to learn how XOR works, then try encrypting some text!** 
