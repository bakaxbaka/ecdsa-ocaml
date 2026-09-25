% Analyze r values from verified dump_rsz CSV output.  Usage:
%   octave --quiet --eval "bit_bias('rsz_database.csv')"
function bit_bias(csv_path)
  fid = fopen(csv_path, 'r');
  if fid < 0, error('cannot open %s', csv_path); end
  unwind_protect
    fgetl(fid); % header
    rows = [];
    while true
      line = fgetl(fid);
      if ~ischar(line), break; end
      columns = strsplit(line, ',');
      if numel(columns) == 10 && strcmp(columns{9}, 'true') && ~isempty(columns{5})
        rows(end + 1, :) = hex_to_bits(columns{5}, 256);
      end
    end
  unwind_protect_cleanup
    fclose(fid);
  end_unwind_protect
  nrows = size(rows, 1);
  if nrows == 0, error('no verified r values found'); end
  p = bit_bias_pvalue(rows);
  printf('verified signatures: %d\nchi-square p-value: %.12g\n', nrows, p);
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

function p = bit_bias_pvalue(bits)
  n = size(bits, 1);
  ones = sum(bits, 1);
  chi2 = sum((ones - n / 2) .^ 2) / (n / 2);
  p = 1 - chi2cdf(chi2, 256);
end
