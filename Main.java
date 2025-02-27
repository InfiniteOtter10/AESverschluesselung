import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Wählen Sie den Modus: (1) Verschlüsseln (2) Entschlüsseln");
        int modus = scanner.nextInt();
        scanner.nextLine(); // Zeilenumbruch einlesen

        if (modus == 1) {
            System.out.println("Geben Sie den zu verschlüsselnden Text ein:");
            String klartext = scanner.nextLine();

            try {
                // Schlüssel und IV generieren
                SecretKey geheimerSchlüssel = AESUtil.generateKey(256);
                byte[] iv = AESUtil.generateIV();

                // Text verschlüsseln
                String verschluesselterText = AESUtil.encrypt(klartext, geheimerSchlüssel, iv);

                // Schlüssel und IV in Base64 kodieren
                String base64Schluessel = Base64.getEncoder().encodeToString(geheimerSchlüssel.getEncoded());
                String base64IV = Base64.getEncoder().encodeToString(iv);

                System.out.println("Verschlüsselter Text: " + verschluesselterText);
                System.out.println("Schlüssel (Base64): " + base64Schluessel);
                System.out.println("IV (Base64): " + base64IV);
            } catch (Exception e) {
                System.err.println("Fehler bei der Verschlüsselung: " + e.getMessage());
            }
        } else if (modus == 2) {
            System.out.println("Geben Sie den zu entschlüsselnden Text ein:");
            String verschluesselterText = scanner.nextLine();

            System.out.println("Geben Sie den Schlüssel (Base64) ein:");
            String base64Schluessel = scanner.nextLine();

            System.out.println("Geben Sie den IV (Base64) ein:");
            String base64IV = scanner.nextLine();

            try {
                // Base64-kodierte Schlüssel und IV dekodieren
                byte[] schluesselBytes = Base64.getDecoder().decode(base64Schluessel);
                byte[] iv = Base64.getDecoder().decode(base64IV);

                // Geheimen Schlüssel rekonstruieren
                SecretKey geheimerSchlüssel = new SecretKeySpec(schluesselBytes, 0, schluesselBytes.length, "AES");

                // Text entschlüsseln
                String entschluesselterText = AESUtil.decrypt(verschluesselterText, geheimerSchlüssel, iv);

                System.out.println("Entschlüsselter Text: " + entschluesselterText);
            } catch (Exception e) {
                System.err.println("Fehler bei der Entschlüsselung: " + e.getMessage());
            }
        } else {
            System.out.println("Ungültige Auswahl. Bitte wählen Sie 1 oder 2.");
        }

        scanner.close();
    }
}

class AESUtil {
    // Generiert einen AES-Schlüssel mit der angegebenen Länge
    public static SecretKey generateKey(int n) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    // Generiert einen Initialisierungsvektor (IV)
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Verschlüsselt den Klartext mit dem gegebenen Schlüssel und IV
    public static String encrypt(String input, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // Entschlüsselt den verschlüsselten Text mit dem gegebenen Schlüssel und IV
    public static String decrypt(String cipherText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
}
//code wurde zu großen Teilen aus diesem Video von WhiteBadCodes entnommen: 
//https://www.youtube.com/watch?v=J1RmZZEkN0k&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa