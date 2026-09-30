\\ bench.gp — PARI/GP representative workload benchmarks
\\ prints "RESULT key value" lines (value = seconds or ops/s)

timer(1);

bench_modexp() = {
  my(p = 2^256 - 2^32 - 977, a = Mod(12345, p), e = 2^255 + 7, t0 = getabstime(), n = 2000);
  for(i = 1, n, a = Mod(7, p)^e);
  my(dt = (getabstime() - t0));
  printf("RESULT pari_modexp256_us_per_op %.6g\n", 1000.0*dt/n);
  printf("RESULT pari_modexp256_ops_s %.6g\n", 1.0*n/(dt/1000));
};

bench_inv() = {
  my(p = 2^256 - 2^32 - 977, t0 = getabstime(), n = 5000);
  for(i = 1, n, lift(1/Mod(i+12345, p)));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_modinv_ops_s %.6g\n", 1.0*n/(dt/1000));
};

bench_gcd() = {
  my(t0 = getabstime(), n = 40000, a = 2^256 - 189, b = 2^240 + 12345);
  for(i = 1, n, gcd(a + i, b + 2*i));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_gcd256_ops_s %.6g\n", 1.0*n/(dt/1000));
};

bench_prime() = {
  my(t0 = getabstime(), n = 200);
  for(i = 1, n, isprime(2^256 - 189 + 2*i));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_isprime256_us_per_op %.6g\n", 1000.0*dt/n);
};

bench_factor() = {
  my(t0 = getabstime(), n = 200);
  for(i = 1, n, factor(2^127 - 1 + 0));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_factor2_127m1_ops_s %.6g\n", 1.0*n/(dt/1000));
};

bench_znlog() = {
  my(p = 1000003, g = znprimroot(p), t0 = getabstime(), n = 50);
  for(i = 1, n, znlog(Mod(i+7, p), Mod(g, p)));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_znlog_p1e6_us_per_op %.6g\n", 1000.0*dt/n);
};

bench_ec() = {
  my(p = 2^256 - 2^32 - 977);
  my(E = ellinit([0, 7] * Mod(1, p)));
  my(G = [Mod(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, p), Mod(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, p)]);
  my(t0 = getabstime(), n = 2000);
  for(i = 1, n, ellmul(E, G, 2^128 + i));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_ec_scalarmult_ops_s %.6g\n", 1.0*n/(dt/1000));
};

bench_poly() = {
  my(t0 = getabstime(), n = 10000);
  my(f = sum(i=0, 100, (i+1)*x^i), g = sum(i=0, 100, (101-i)*x^i));
  for(i = 1, n, f*g);
  my(dt = (getabstime() - t0));
  printf("RESULT pari_polymul_deg100_ops_s %.6g\n", 1.0*n/(dt/1000));
  t0 = getabstime();
  for(i = 1, 20, gcd(f*(x+3), f*(x+5)));
  dt = (getabstime() - t0);
  printf("RESULT pari_polygcd_deg101_ops_s %.6g\n", 1.0*20/(dt/1000));
};

bench_bigint() = {
  my(t0 = getabstime(), n = 20000);
  for(i = 1, n, (2^4096 - 1) * (2^4096 + i));
  my(dt = (getabstime() - t0));
  printf("RESULT pari_mul4096bit_ops_s %.6g\n", 1.0*n/(dt/1000));
  t0 = getabstime();
  for(i = 1, 20, 50000!);
  dt = (getabstime() - t0);
  printf("RESULT pari_fact50000_ms_per_op %.6g\n", 1.0*dt/20);
};

bench_modexp();
bench_inv();
bench_gcd();
bench_prime();
bench_factor();
bench_znlog();
bench_ec();
bench_poly();
bench_bigint();
print("RESULT pari_bench_done 1");
quit;
