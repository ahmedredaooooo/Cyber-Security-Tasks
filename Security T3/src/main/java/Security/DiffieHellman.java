package Security;

import java.util.List;

public class DiffieHellman {
    public int fastPower(long b, int p, int mod)
    {
        long ret = 1;
        if (p == 0) return 1;
        b %= mod;
        while (p > 0)
        {
            if ((p & 1) == 1)
            {
                ret *= b;
                ret %= mod;

            }
            p >>= 1;
            b *= b;
            b %= mod;
        }
        return (int)ret;
    }
    public int calculatePublicKey(int q, int alpha, int x) {
        return fastPower(alpha, x, q); // y
    }
    public int calculateSecretKey(int q, int x, int y) {
        return fastPower(y, x, q);
    }
    public List<Integer> getKeys(int q, int alpha, int xa, int xb) {
        int ya = calculatePublicKey(q, alpha, xa);
        int yb = calculatePublicKey(q, alpha, xb);
        return List.of(calculateSecretKey(q, xa, yb), calculateSecretKey(q, xb, ya));
    }
}
