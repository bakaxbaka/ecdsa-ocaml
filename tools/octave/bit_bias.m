% Analyze r values from verified dump_rsz CSV output.  Usage:
%   octave --quiet --eval "bit_bias('rsz_database.csv')"
%
% Both the historical nine-column dataset (r, z, ecdsa_valid) and the current
% ten-column dump_rsz output (r_hex, z_hex, ecdsa_valid, note) are accepted.
function bit_bias(csv_path)
  fid = fopen(csv_path, 'r');
  if fid < 0, error('cannot open %s', csv_path); end
  unwind_protect
    header = strsplit(fgetl(fid), ',');
    r_column = column_index(header, {'r_hex', 'r'});
    valid_column = column_index(header, {'ecdsa_valid'});
    rows = [];
    while true
      line = fgetl(fid);
      if ~ischar(line), break; end
      columns = strsplit(line, ',');
      if numel(columns) >= max(r_column, valid_column) ...
          && strcmp(columns{valid_column}, 'true') && ~isempty(columns{r_column})
        rows(end + 1, :) = hex_to_bits(columns{r_column}, 256);
      end
    end
  unwind_protect_cleanup
    fclose(fid);
  end_unwind_protect
  nrows = size(rows, 1);
  if nrows == 0, error('no verified r values found'); end
  [chi2, lower_p, upper_p] = bit_bias_stats(rows);
  printf(['verified signatures: %d\n' ...
          'bit-position statistic: %.12g\n' ...
          'reference: 2 * statistic ~ chi-square(256)\n' ...
          'lower-tail p-value: %.12g\nupper-tail p-value: %.12g\n'], ...
         nrows, chi2, lower_p, upper_p);
end

function index = column_index(header, names)
  index = 0;
  for k = 1:numel(names)
    found = find(strcmp(header, names{k}), 1);
    if ~isempty(found)
      index = found;
      return;
    end
  end
  error('CSV is missing required column: %s', names{1});
end

function bits = hex_to_bits(h, nb)
  h = lower(h); h = h(h ~= ' ');
  if length(h) * 4 < nb
    h = [repmat('0', 1, nb - length(h) * 4), h];
  elseif length(h) * 4 > nb
    h = h(end - nb / 4 + 1:end);
  end
  bits = zeros(1, nb);
  for k = 1:(nb / 4)
    d = hex2dec(h(k)); % Exactly one hex digit: no precision loss.
    bits((k - 1) * 4 + (1:4)) = bitget(d, 4:-1:1);
  end
end

function [chi2, lower_p, upper_p] = bit_bias_stats(bits)
  n = size(bits, 1);
  ones = sum(bits, 1);
  chi2 = sum((ones - n / 2) .^ 2) / (n / 2);
  % For a Bernoulli(0.5) bit count, Var(ones) = n / 4 while the
  % denominator above is n / 2.  Each term is therefore asymptotically
  % one half of chi-square(1), not chi-square(1).  Rescaling the statistic
  % gives the usual chi-square(256) reference distribution.
  lower_p = chi2cdf(2 * chi2, 256);
  upper_p = 1 - lower_p;
end
