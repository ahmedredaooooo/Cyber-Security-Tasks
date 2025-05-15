package Security;

public class RSA {

    public int eGCD(long A1 , long A2, long A3 , long B1, long B2, long B3) {
        if (B3 == 1) {
            return (int)B2;
        } else if (B3 == 0) {
            return -1;
        }
        long Q = A3 / B3;
        return eGCD(B1, B2, B3, (A1 - Q * B1), (A2 - Q * B2), (A3 % B3));
    }
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

    public int encrypt(int p, int q, int M, int e) {
        return fastPower(M, e,  p * q);
    }

    public int decrypt(int p, int q, int C, int e) {
        int phi =  (p - 1) * (q - 1);
        int d = eGCD(1, 0, phi, 0 , 1, e);
        if (d < 0)
        {
            d %= phi;
            d += phi;
        }
        return fastPower(C, d,  p * q);
    }

    public static void main(String [] argc)
    {
        RSA r = new RSA();
        System.out.println(r.eGCD(1,0,26,0,1,23));
        System.out.println(r.fastPower(18537, 17, 257 * 337));
    }
}
