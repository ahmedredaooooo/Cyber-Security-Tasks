package Security;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PlayfairCipher {
    private final char[][] keyMatrix;

    public PlayfairCipher(String key) {
        keyMatrix = generateKeyMatrix(key);
    }

    // Generates the 5x5 key matrix for Playfair Cipher
    private char[][] generateKeyMatrix(String key) {
        Set<Character> used = new LinkedHashSet<>();
        key = key.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");

        for (char c : key.toCharArray()) {
            used.add(c);
        }

        for (char c = 'A'; c <= 'Z'; c++) {
            if (c != 'J') used.add(c);
        }

        char[][] matrix = new char[5][5];
        Iterator<Character> it = used.iterator();
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                matrix[i][j] = it.next();
            }
        }
        return matrix;
    }

    // Prepares the text by removing invalid characters, replacing 'J' with 'I', and ensuring even length
    private String prepareText(String text) {
        text = text.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            sb.append(text.charAt(i));
            // Insert 'X' if two consecutive letters are the same
            if (i < text.length() - 1 && text.charAt(i) == text.charAt(i + 1) && text.charAt(i) != 'X') {
                sb.append('X');
            }
        }
        // Ensure even length
        if (sb.length() % 2 != 0) {
            sb.append('X');
        }
        return sb.toString();
    }

    private int[][] memo = new int[26][];
    // TODO: Implement this method to find the position of a character in the key matrix
    private int[] findPosition(char c) {
        // Students should complete this part
        if (memo[c - 'A'] != null) return memo[c - 'A'];
        for (int i = 0; i < keyMatrix.length; i++)
            for (int j = 0; j < keyMatrix[i].length; j++)
                memo[keyMatrix[i][j] - 'A'] = new int[]{i, j};
        return memo[c - 'A'];
    }

    // Encrypts the given plaintext using the Playfair cipher algorithm
    public String encrypt(String text) {
        text = prepareText(text);
        StringBuilder encryptedText = new StringBuilder();

        for (int i = 0; i < text.length(); i += 2) {
            int[] pos1 = findPosition(text.charAt(i));
            int[] pos2 = findPosition(text.charAt(i + 1));

            if (pos1 == null || pos2 == null) continue; // Safety check

            if (pos1[0] == pos2[0]) {  // Same row
                encryptedText.append(keyMatrix[pos1[0]][(pos1[1] + 1) % 5]);
                encryptedText.append(keyMatrix[pos2[0]][(pos2[1] + 1) % 5]);
            } else if (pos1[1] == pos2[1]) {  // Same column
                encryptedText.append(keyMatrix[(pos1[0] + 1) % 5][pos1[1]]);
                encryptedText.append(keyMatrix[(pos2[0] + 1) % 5][pos2[1]]);
            } else {  // Rectangle swap
                encryptedText.append(keyMatrix[pos1[0]][pos2[1]]);
                encryptedText.append(keyMatrix[pos2[0]][pos1[1]]);
            }
        }
        return encryptedText.toString();
    }

    // TODO: Implement this method to decrypt the ciphertext back to plaintext
    public String decrypt(String text) {
        // Students should complete this part
        StringBuilder decryptedText = new StringBuilder();

        if (text.length() % 2 == 1)
            text = text.replaceAll("[A-Z]$", "");
        assert(text.length() % 2 == 0);
        for (int i = 0; i < text.length(); i += 2)
        {
             int[] p1 = findPosition(text.charAt(i));
             int[] p2 = findPosition(text.charAt(i + 1));
             assert(!Arrays.equals(p1, p2));
             if (p1[0] == p2[0])
             {
                 decryptedText.append(keyMatrix[p1[0]][(p1[1] + 4) % 5]);
                 decryptedText.append(keyMatrix[p2[0]][(p2[1] + 4) % 5]);
             }
             else if (p1[1] == p2[1])
             {
                 decryptedText.append(keyMatrix[(p1[0] + 4) % 5][p1[1]]);
                 decryptedText.append(keyMatrix[(p2[0] + 4) % 5][p2[1]]);
             }
             else
             {
                 decryptedText.append(keyMatrix[p1[0]][p2[1]]);
                 decryptedText.append(keyMatrix[p2[0]][p1[1]]);
             }
        }
        text = decryptedText.toString().toUpperCase().replaceAll("([A-Z])X\\1", "$1$1").replaceAll("X$", "").replace('J', 'I');

        return text;
    }
}
