function f = fib_file(n)
  % fib_file.m — proves function-file script execution works
  if n <= 1
    f = n;
  else
    f = fib_file(n - 1) + fib_file(n - 2);
  end
end
