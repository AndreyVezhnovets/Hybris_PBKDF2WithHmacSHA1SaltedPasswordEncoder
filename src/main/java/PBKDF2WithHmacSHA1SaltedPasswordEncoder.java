import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class PBKDF2WithHmacSHA1SaltedPasswordEncoder {
    private int iterations = 1000;
    private int keyLength = 512;
    private String keyAlgorithm = "PBKDF2WithHmacSHA1";
    private int saltLength = 16;
    private String saltAlgorithm = "SHA1PRNG";


    public String encode(String password) throws NoSuchAlgorithmException {
        byte[] salt = this.generateSalt();
        byte[] hash = this.calculateHash(password, salt, this.iterations, this.keyLength);
        return (new PBKDF2WithHmacSHA1SaltedPasswordEncoder.EncodedHash(this.iterations, salt, hash)).toString();
    }

    public boolean check(String encoded, String plain) {
        PBKDF2WithHmacSHA1SaltedPasswordEncoder.EncodedHash parsedEncodedHash = new PBKDF2WithHmacSHA1SaltedPasswordEncoder.EncodedHash(encoded);
        byte[] hash = this.calculateHash(plain, parsedEncodedHash.salt, parsedEncodedHash.iterations, parsedEncodedHash.hash.length * 8);
        return Arrays.equals(parsedEncodedHash.hash, hash);
    }

    protected byte[] calculateHash(String password, byte[] salt, int iterations, int keyLength) {
        String _password = password == null ? "" : password;
        try {
            PBEKeySpec spec = new PBEKeySpec(_password.toCharArray(), salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return factory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException var7) {
            throw new IllegalArgumentException(var7);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
    }

    private byte[] generateSalt() throws NoSuchAlgorithmException {
        byte[] salt = new byte[this.saltLength];
        SecureRandom.getInstance(this.saltAlgorithm).nextBytes(salt);
        return salt;
    }

    protected static class EncodedHash {
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        EncodedHash(String encoded) {
            try {
                String[] parts = encoded.split(":");
                this.iterations = Integer.parseInt(parts[0]);
                this.salt = Hex.decode(parts[1]);
                this.hash = Hex.decode(parts[2]);
            } catch (Exception var3) {
                throw new RuntimeException("Invalid salt and/or hash");
            }
        }

        EncodedHash(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.hash = hash;
            this.salt = salt;
        }

        public String toString() {
            return this.iterations + ":" + new String(Hex.encode(this.salt)) + ":" + new String(Hex.encode(this.hash));
        }

    }
}
