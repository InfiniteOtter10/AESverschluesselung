import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AESExample {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Soll (1) Verschluesseln (2) Entschluesseln werden");
        int mode = scanner.nextInt();
        scanner.nextLine(); //Auswahl speichern

        if (mode == 1) { //Verschluesselung
            System.out.println("Klartext eingeben:");
            String plaintext = scanner.nextLine();

            SecretKey secretKey = generateKey(); //Schluessel generieren
            byte[] iv = generateIV(); //IV generieren

            String encryptedText = encrypt(plaintext, secretKey, iv); //den eingegeben Klartext mit Schluesseln und IV verschluesseln
            int paddingSize = getPaddingSize(plaintext); //Padding groesse festlegen
            
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded()); //Text zu einem String aus Buchstaben, Zahlen und Zeichen unwandeln
            String encodedIV = Base64.getEncoder().encodeToString(iv); //IV zu einem String umwandeln
            
            System.out.println("Verschluesselter Text: " + encryptedText);
            System.out.println("Schluessel (Base64): " + encodedKey);
            System.out.println("IV (Base64): " + encodedIV);
            System.out.println("Padding Groesse: " + paddingSize + " Bytes"); //alle Were ausgeben
        } else if (mode == 2) { //entschluesseln
            System.out.println("verschluesselten Text eingeben:");
            String encryptedText = scanner.nextLine();
            System.out.println("Schluessel (Base64) eingeben:");
            String encodedKey = scanner.nextLine();
            System.out.println("IV (Base64) eingeben:"); 
            String encodedIV = scanner.nextLine();
            
            SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(encodedKey), "AES"); //Schluessel entschluesseln
            byte[] iv = Base64.getDecoder().decode(encodedIV); //IV entschluesseln
            
            String decryptedText = decrypt(encryptedText, secretKey, iv); //den verschluesselten Text mit Schluessel und IV entschluesseln
            System.out.println("Entschluesselter Text: " + decryptedText);
        } else {
            System.out.println("Ungueltige Eingabe.");
        }
        scanner.close();
    }
    
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey(); //Schluessel generieren
    }
    
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv; //IV generieren
    }
    
    public static String encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(cipherText); //Padding verschluesseln
    }
    
    public static String decrypt(String cipherText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //Padding Typ festlegen
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        int paddingSize = getPaddingSize(new String(plainText)); //Padding groesse errechnen
        System.out.println("Padding Groesse: " + paddingSize + " Bytes");
        return new String(plainText);
    }
    
    public static int getPaddingSize(String text) {
        int blockSize = 16; // AES Blockgröße in Bytes
        int paddingSize = blockSize - (text.length() % blockSize);
        return paddingSize == blockSize ? 0 : paddingSize;
    }
}
//code wurde zu großen Teilen aus diesem Video von WhiteBadCodes entnommen: 
//https://www.youtube.com/watch?v=J1RmZZEkN0k&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa
