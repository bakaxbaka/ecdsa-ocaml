% check_octave.m — verification + micro-benchmarks for the crypto workbench
% Deterministic computations (no RNG) so Python/NumPy can cross-check exactly.
% Emits "RESULT key value" lines on stdout.

printf("RESULT octave_version %s\n", version());

% ---- matrix multiply: deterministic 500x500, cross-checked vs numpy ----
N = 500;
A = reshape(1:N*N, N, N) / (N*N + 1);   % column-major fill A(i,j)=((j-1)*N+i)/(N*N+1)
tic; C = A * A'; t_mm = toc;
printf("RESULT matmul500_s %.6f\n", t_mm);
printf("RESULT matmul500_sum %.10e\n", sum(C(:)));
printf("RESULT matmul500_c11 %.10e\n", C(1,1));
printf("RESULT matmul500_c250_250 %.10e\n", C(250,250));
printf("RESULT matmul500_trace %.10e\n", trace(C));

% ---- FFT 2^16, deterministic signal ----
M = 65536;
k = (0:M-1)';
x = sin(2*pi*k/97) + 0.5*sin(2*pi*k/13);
tic; y = fft(x); t_fft = toc;
printf("RESULT fft65536_s %.6f\n", t_fft);
printf("RESULT fft_maxabs %.10e\n", max(abs(y)));
printf("RESULT fft_sum_real_head %.10e\n", sum(real(y(1:8))));
printf("RESULT fft_abs_y2 %.10e\n", abs(y(2)));

% ---- polynomial operations ----
p1 = [1 2 3 4]; p2 = [5 -1 0 7];
c = conv(p1, p2);
printf("RESULT poly_conv %s\n", sprintf("%d ", c));
r = roots([1 -6 11 -6]);
printf("RESULT poly_roots_sum %.10e\n", sum(r));
printf("RESULT poly_roots_prod %.10e\n", prod(r));
pv = polyval([1 2 3 4], 3);
printf("RESULT polyval_3 %d\n", pv);

% ---- numerical linear algebra ----
Mt = [4 1 0 2; 1 5 2 0; 0 2 6 1; 2 0 1 7];
bb = [1; 2; 3; 4];
sol = Mt \ bb;
printf("RESULT solve_sum %.10e\n", sum(sol));
ev = eig(Mt);
printf("RESULT eig_sum %.10e\n", sum(ev));          % == trace
printf("RESULT eig_max %.10e\n", max(ev));
[Uu, S, V] = svd(Mt);
printf("RESULT svd_s1 %.10e\n", S(1,1));
printf("RESULT svd_s4 %.10e\n", S(4,4));
printf("RESULT rank %d\n", rank(Mt));
Mi = inv(Mt);
printf("RESULT inv_trace %.10e\n", trace(Mi));
printf("RESULT det %.10e\n", det(Mt));

% ---- function-file execution check ----
addpath(fileparts(mfilename("fullpath")));
printf("RESULT fib20 %d\n", fib_file(20));

% ---- benchmark timings (single run, thread count from env) ----
[~, ob] = system("printenv OPENBLAS_NUM_THREADS");
printf("RESULT openblas_threads_env %s\n", strtrim(ob));
for sz = [256, 512, 1024]
  B = reshape(1:sz*sz, sz, sz) / (sz*sz + 1);
  tic; D = B * B'; tt = toc;
  gflops = 2 * double(sz)^3 / tt / 1e9;
  printf("RESULT matmul%d_s %.6f\n", sz, tt);
  printf("RESULT matmul%d_gflops %.3f\n", sz, gflops);
end
xf = sin(2*pi*(0:2^20-1)'/97);
tic; yf = fft(xf); tf = toc;
printf("RESULT fft1M_s %.6f\n", tf);

printf("RESULT octave_done 1\n");
exit(0);
