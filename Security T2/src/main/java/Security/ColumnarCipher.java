package Security;
import java.util.*;

public class ColumnarCipher {

    public List<Integer> analyse(String plainText, String cipherText) {
        // TODO: Analyze the plainText and cipherText to determine the key(s)
        int ptSize = plainText.length();
        int ctSize = cipherText.length();
        int[] freq = new int[ptSize];
        int[] mx = {-1, -1};

        for (int i = 1; i < ctSize; ++i)
        {
            char f = cipherText.charAt(i - 1);
            char s = cipherText.charAt(i);
            int cols = plainText.indexOf(s) - plainText.indexOf(f);
            if (cols < 0) continue;
            freq[cols]++;
            if (freq[cols] > mx[1])
            {
                mx[0] = cols;
                mx[1] = freq[cols];
            }
        }
        int cols = mx[0];
        int rows = ctSize / cols;

        int count = 0;
        StringBuilder[] col = new StringBuilder[cols];

        for (int i = 0; i < cols; i++)
            col[i] = new StringBuilder();

        for (int i = 0; i < rows; i++)
            for (int j = 0; j < cols; j++)
                if (count >= ptSize)
                    col[j].append('x');
                else
                    col[j].append(plainText.charAt(count++));

        ArrayList<Integer> Key = new ArrayList<Integer>(cols);
        for (int i = 0; i < cols; i++)
            Key.add(0);
        for (int i = 0; i < cols; ++i)
        {
            String tmp = cipherText.substring(i * rows, i * rows + rows);
            for (int j = 0; j < cols; j++)
                if (tmp.equals(col[j].toString()))
                {
                    Key.set(j, i + 1);
                    break;
                }
        }

        return Key; // Placeholder return
    }

    public String decrypt(String cipherText, List<Integer> key) {
        int cipherSize = cipherText.length();
        int rows = (int) Math.ceil((double) cipherSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        int remainingCols = cipherSize % key.size();
        for (int i = 0; i < key.size(); ++i) {
            for (int j = 0; j < rows; ++j) {
                if (remainingCols != 0 && j == rows - 1 && keyMap.get(i) >= remainingCols) continue;
                grid[j][keyMap.get(i)] = cipherText.charAt(count++);
            }
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < key.size(); ++j) {
                result.append(grid[i][j]);
            }
        }
        return result.toString().toUpperCase().trim();
    }

    public String encrypt(String plainText, List<Integer> key) {
        int ptSize = plainText.length();
        int rows = (int) Math.ceil((double) ptSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                if (count >= ptSize) {
                    grid[i][j] = 'x';
                } else {
                    grid[i][j] = plainText.charAt(count++);
                }
            }
        }

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        StringBuilder cipherText = new StringBuilder();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                cipherText.append(Character.toUpperCase(grid[j][keyMap.get(i)]));
            }
        }
        return cipherText.toString();
    }
}
