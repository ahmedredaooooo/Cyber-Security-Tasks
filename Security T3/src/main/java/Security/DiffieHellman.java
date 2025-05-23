package Security;

import java.util.List;

public class DiffieHellman {


    public int calculatePublicKey(int q, int alpha, int x) {
        return RSA.fastPower(alpha, x, q); // y
    }
    public int calculateSecretKey(int q, int x, int y) {
        return RSA.fastPower(y, x, q);
    }
    public List<Integer> getKeys(int q, int alpha, int xa, int xb) {
        int ya = calculatePublicKey(q, alpha, xa);
        int yb = calculatePublicKey(q, alpha, xb);
        return List.of(calculateSecretKey(q, xa, yb), calculateSecretKey(q, xb, ya));
    }
}
