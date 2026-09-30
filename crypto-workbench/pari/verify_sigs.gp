\\ verify_sigs.gp — independent ECDSA verification using PARI/GP elliptic arithmetic
\\ usage: PARI_SIGS=<input_file> gp -q pari/verify_sigs.gp
\\ input lines: [r, s, z, "pubkeyhex"]   (decimal integers + hex pubkey string)
\\ output lines: "<index> OK" or "<index> FAIL"

p = 2^256 - 2^32 - 977;
n = 2^256 - 432420386565659656852420866394968145599;
E = ellinit([0, 7] * Mod(1, p));
G = [Mod(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, p), Mod(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, p)];
HEXDV = Vec("0123456789abcdef");

hexdigit(c) = { my(k = 1); while(k <= 16 && HEXDV[k] != c, k++); if(k > 16, error("bad hex digit")); k - 1; };

hex2valv(V) = { my(v = 0); for(i = 1, #V, v = v*16 + hexdigit(V[i])); v; };

hex2val(h) = { hex2valv(Vec(h)); };

decompress(pkhex) = {
  my(V = Vec(pkhex), x, y);
  if(#V == 66,
    x = hex2valv(V[3..66]);
    y = lift(sqrt(Mod(x^3 + 7, p)));
    if(y % 2 != hex2valv(V[1..2]) - 2, y = p - y);
    [Mod(x, p), Mod(y, p)],
    if(#V == 130,
      x = hex2valv(V[3..66]); y = hex2valv(V[67..130]);
      [Mod(x, p), Mod(y, p)],
      error("bad pubkey len")));
};

verify1(r, s, z, Q) = {
  if(r < 1 || r >= n || s < 1 || s >= n, return(0));
  my(w = 1/Mod(s, n), u1 = lift(Mod(z, n)*w), u2 = lift(Mod(r, n)*w));
  my(R = elladd(E, ellmul(E, G, u1), ellmul(E, Q, u2)));
  if(type(R) != "t_VEC", return(0));
  lift(R[1]) % n == r;
};

main(f) = {
  my(lines = readvec(f), idx = 0);
  for(k = 1, #lines,
    my(L = lines[k]);
    if(type(L) == "t_VEC" && #L >= 4,
      idx++;
      print(idx - 1, " ", if(verify1(L[1], L[2], L[3], decompress(L[4])), "OK", "FAIL"));
    );
  );
};

main(getenv("PARI_SIGS"));
quit;
