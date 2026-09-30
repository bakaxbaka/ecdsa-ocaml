function analyze_signatures(csv_file)
    fprintf('Loading signature data from %s...\n', csv_file);

    fid = fopen(csv_file, 'r');
    if fid < 0
        error('Cannot open %s', csv_file);
    end
    fgetl(fid);  % skip header
    C = textscan(fid, '%s %d %s %s %s %d', 'Delimiter', ',');
    fclose(fid);

    txid        = C{1};
    input_index = C{2};
    r_hex       = C{3};
    s_hex       = C{4};
    % z_placeholder = C{5};   % unused: needs proper sighash
    sighash     = C{6};

    n = length(txid);
    fprintf('Loaded %d signatures\n\n', n);

    % ---- Parse hex -> 256-bit matrices directly (no float loss) ----
    r_bits = zeros(n, 256);
    s_bits = zeros(n, 256);
    for i = 1:n
        r_bits(i,:) = hex_to_bits(r_hex{i}, 256);
        s_bits(i,:) = hex_to_bits(s_hex{i}, 256);
    end

    % ---- 1. Repeated r (nonce reuse) ----
    fprintf('\n=== REPEATED R VALUES (Potential Nonce Reuse) ===\n');
    [unique_r, ~, ic] = unique(r_hex);          % works on cellstr
    counts = accumarray(ic, 1);
    rep_idx = find(counts > 1);
    if isempty(rep_idx)
        fprintf('No repeated r values found\n');
    else
        fprintf('Found %d repeated r values:\n', numel(rep_idx));
        for k = rep_idx(:)'
            first = find(strcmp(r_hex, unique_r{k}), 1);
            fprintf('  r=%s appears %d times (first: tx=%s input=%d)\n', ...
                unique_r{k}, counts(k), txid{first}, input_index(first));
        end
    end

    % ---- 2. High-S / Low-S (BIP62) ----
    fprintf('\n=== HIGH-S vs LOW-S ANALYSIS ===\n');
    half_n = '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';
    is_high = false(n,1);
    for i = 1:n
        is_high(i) = hexcmp(s_hex{i}, half_n) > 0;
    end
    nh = sum(is_high);
    fprintf('Total signatures:  %d\n', n);
    fprintf('High-S signatures: %d (%.2f%%)\n', nh,       100*nh/n);
    fprintf('Low-S signatures:  %d (%.2f%%)\n', n-nh, 100*(n-nh)/n);

    % ---- 3. Sighash distribution ----
    fprintf('\n=== SIGHASH TYPE DISTRIBUTION ===\n');
    [ush, ~, sh_ic] = unique(sighash);
    sh_counts = accumarray(sh_ic, 1);
    for i = 1:numel(ush)
        fprintf('  SIGHASH_%s: %d (%.2f%%)\n', ...
            get_sighash_name(ush(i)), sh_counts(i), 100*sh_counts(i)/n);
    end

    % ---- 4. Bit-level entropy ----
    fprintf('\n=== BIT-LEVEL ENTROPY ANALYSIS ===\n');
    fprintf('R total bit entropy: %.4f bits (max 256)\n', total_bit_entropy(r_bits));
    fprintf('S total bit entropy: %.4f bits (max 256)\n', total_bit_entropy(s_bits));

    % ---- 5. Hamming distance between consecutive signatures ----
    if n > 1
        fprintf('\n=== HAMMING DISTANCE ANALYSIS ===\n');
        rd = sum(xor(r_bits(1:end-1,:), r_bits(2:end,:)), 2);
        sd = sum(xor(s_bits(1:end-1,:), s_bits(2:end,:)), 2);
        fprintf('R: mean=%.2f std=%.2f min=%d max=%d\n', ...
            mean(rd), std(rd), min(rd), max(rd));
        fprintf('S: mean=%.2f std=%.2f min=%d max=%d\n', ...
            mean(sd), std(sd), min(sd), max(sd));
    end

    % ---- 6. MSB patterns ----
    fprintf('\n=== MOST SIGNIFICANT BIT PATTERNS ===\n');
    analyze_msb_patterns(r_bits, 'R');
    analyze_msb_patterns(s_bits, 'S');

    % ---- 7. Small values (r < 2^255 etc.) ----
    fprintf('\n=== SMALL VALUE ANALYSIS ===\n');
    % r < 2^255  <=>  the top bit (bit 1 of the 256-bit vector) is 0
    nr = sum(r_bits(:,1) == 0);
    ns = sum(s_bits(:,1) == 0);
    fprintf('R values < 2^255: %d (%.2f%%)\n', nr, 100*nr/n);
    fprintf('S values < 2^255: %d (%.2f%%)\n', ns, 100*ns/n);

    fprintf('\n=== ANALYSIS COMPLETE ===\n');
end

% ------------------------------------------------------------------
% Helpers
% ------------------------------------------------------------------

function bits = hex_to_bits(hexstr, nbits)
    hexstr = lower(hexstr);
    hexstr = hexstr(hexstr ~= ' ');          % tolerate spaces
    if length(hexstr)*4 < nbits
        hexstr = [repmat('0', 1, nbits - length(hexstr)*4), hexstr];
    elseif length(hexstr)*4 > nbits
        hexstr = hexstr(end - nbits/4 + 1 : end);
    end
    bits = zeros(1, nbits);
    for k = 1:(nbits/4)
        d = hex2dec(hexstr(k));              % 0..15: exact
        bits((k-1)*4 + (1:4)) = bitget(d, 4:-1:1);
    end
end

function c = hexcmp(a, b)
    % Lexicographic compare of equal-length lowercase hex strings.
    a = lower(a); b = lower(b);
    if length(a) < length(b), a = [repmat('0',1,length(b)-length(a)), a]; end
    if length(b) < length(a), b = [repmat('0',1,length(a)-length(b)), b]; end
    if     strcmp(a,b), c =  0;
    elseif a < b,       c = -1;
    else                c =  1;
    end
end

function e = total_bit_entropy(bits)
    p = mean(bits, 1);
    q = 1 - p;
    term = zeros(size(p));
    m = (p > 0) & (q > 0);
    term(m) = -p(m).*log2(p(m)) - q(m).*log2(q(m));
    e = sum(term);
end

function analyze_msb_patterns(bits, name)
    msb8 = bits(:,1:8);
    pat = zeros(256,1);
    w = 2.^(7:-1:0);
    for i = 1:size(msb8,1)
        idx = sum(msb8(i,:) .* w) + 1;
        pat(idx) = pat(idx) + 1;
    end
    [sc, si] = sort(pat, 'descend');
    fprintf('%s most common MSB 8-bit patterns:\n', name);
    for i = 1:min(5, numel(sc))
        if sc(i) == 0, break; end
        fprintf('  %s: %d (%.2f%%)\n', ...
            dec2bin(si(i)-1, 8), sc(i), 100*sc(i)/sum(pat));
    end
end

function name = get_sighash_name(val)
    switch val
        case 1,   name = 'ALL';
        case 2,   name = 'NONE';
        case 3,   name = 'SINGLE';
        case 129, name = 'ALL|ANYONECANPAY';      % 0x81
        case 130, name = 'NONE|ANYONECANPAY';     % 0x82
        case 131, name = 'SINGLE|ANYONECANPAY';   % 0x83
        otherwise, name = sprintf('UNKNOWN(%d)', val);
    end
end
