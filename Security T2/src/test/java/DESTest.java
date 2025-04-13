import Security.DES;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class DESTest {

    @Test
    void testEncryption() {
        DES des = new DES();
        String key = "133457799BBCDFF1"; // 64-bit key in hex
        String plainText = "0123456789ABCDEF"; // 64-bit block in hex
        String expectedCipherText = "85E813540F0AB405"; // Known output from DES example
        String actualCipherText = des.encrypt(plainText, key);
        assertEquals(expectedCipherText.toUpperCase(), actualCipherText.toUpperCase());
    }

    @Test
    void testDecryption() {
        DES des = new DES();
        String key = "133457799BBCDFF1";
        String cipherText = "85E813540F0AB405";
        String expectedPlainText = "0123456789ABCDEF";
        String actualPlainText = des.decrypt(cipherText, key);
        assertEquals(expectedPlainText.toUpperCase(), actualPlainText.toUpperCase());
    }

    @Test
    void testDifferentKey() {
        DES des = new DES();
        String wrongKey = "A1B2C3D4E5F60708";
        String cipherText = "85E813540F0AB405";
        String result = des.decrypt(cipherText, wrongKey);
        assertNotEquals("0123456789ABCDEF", result);
    }

    @Test
    void testSameEncryptionDecryption() {
        DES des = new DES();
        String key = "AABB09182736CCDD";
        String plainText = "1234567890ABCDEF";
        String encrypted = des.encrypt(plainText, key);
        String decrypted = des.decrypt(encrypted, key);
        assertEquals(plainText.toUpperCase(), decrypted.toUpperCase());
    }


    @Test
    void testBinaryToHex() {
        DES d = new DES();
        assertEquals("00000000000000f1", d.binaryToHex("11110001"));
    }

    @Test
    void testXor() {
        DES d = new DES();
        assertEquals("010101010100", d.xor("101010100111", "111111110011"));
    }

    @Test
    void testGenerateSubKeys() {
        DES d = new DES();
        String[] actuals = d.generateSubKeys(DES.hexToBinary("133457799BBCDFF1"));
        String[] expecteds = {
                "000110110000001011101111111111000111000001110010",
                "011110011010111011011001110110111100100111100101",
                "010101011111110010001010010000101100111110011001",
                "011100101010110111010110110110110011010100011101",
                "011111001110110000000111111010110101001110101000",
                "011000111010010100111110010100000111101100101111",
                "111011001000010010110111111101100001100010111100",
                "111101111000101000111010110000010011101111111011",
                "111000001101101111101011111011011110011110000001",
                "101100011111001101000111101110100100011001001111",
                "001000010101111111010011110111101101001110000110",
                "011101010111000111110101100101000110011111101001",
                "100101111100010111010001111110101011101001000001",
                "010111110100001110110111111100101110011100111010",
                "101111111001000110001101001111010011111100001010",
                "110010110011110110001011000011100001011111110101",
        };

        for (int i = 0; i < 16; i++)
        {
            System.out.println(i + 1);
            assertEquals(expecteds[i], actuals[i]);
        }
   }
}

