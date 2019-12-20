import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        PBKDF2WithHmacSHA1SaltedPasswordEncoder encoder = new PBKDF2WithHmacSHA1SaltedPasswordEncoder();
        String password = "12341234";
        String encodedPassword = encoder.encode(password);
        System.out.println(encoder.check(encodedPassword, password));
        System.out.println(encodedPassword);
    }
}
