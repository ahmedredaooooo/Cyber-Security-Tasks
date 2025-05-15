package Security;
import java.util.*;
import java.util.ArrayList;
import java.util.List;

public class ElGamal {
    public int calculateC1(int alpha, int k, int q) {
        return RSA.fastPower(alpha, k, q);
    }

    public int calculateC2(int y, int k, int q, int M) {
        int K = RSA.fastPower(y, k, q);
        return (M * K) % q;
    }

    public List<Long> encrypt(int q, int alpha, int y, int k, int m)
    {
        long c1 = calculateC1(alpha, k, q);
        long c2 = calculateC2(y, k, q, m);
        return List.of(c1, c2);
    }

    public int decrypt(int c1, int c2, int x, int q)
    {
        return (c2 * RSA.eGCD(1, 0, q, 0, 1, RSA.fastPower(c1, x, q)) % q);
    }
}