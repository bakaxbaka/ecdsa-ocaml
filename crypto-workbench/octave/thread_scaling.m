% thread_scaling.m — careful OpenBLAS thread scaling probe
% 2048x2048 matmul, warmup run, then 3 timed runs; reports min time.
% Env OPENBLAS_NUM_THREADS controls thread count (set by wrapper).
N = 2048;
B = reshape(1:N*N, N, N) / (N*N + 1);
D = B * B';            % warmup (also initializes thread pool)
times = zeros(1, 3);
for rep = 1:3
  tic; D = B * B'; times(rep) = toc;
end
tmin = min(times);
gflops = 2 * double(N)^3 / tmin / 1e9;
printf("RESULT matmul2048_min_s %.6f\n", tmin);
printf("RESULT matmul2048_gflops %.3f\n", gflops);
printf("RESULT threads_env %s\n", getenv("OPENBLAS_NUM_THREADS"));
% FFT scaling too
x = sin(2*pi*(0:2^22-1)'/97);
y = fft(x);   % warmup
ft = zeros(1,3);
for rep = 1:3
  tic; y = fft(x); ft(rep) = toc;
end
printf("RESULT fft4M_min_s %.6f\n", min(ft));
exit(0);
