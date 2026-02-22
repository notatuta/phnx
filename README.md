# phnx - Encryption and Error Correction Tool

phnx combines file encryption with error correction, splitting encrypted files into 8 pieces with built-in redundancy. The original file can be recovered even if one piece is missing, or some pieces are corrupted.

[![C/C++ CI](https://github.com/notatuta/phnx/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/notatuta/phnx/actions/workflows/c-cpp.yml)

## Features

- **Strong Encryption**: Speck128/256 cipher in CTR mode
- **Error Correction**: Extended Binary Golay Code (24,12,8)
- **Resilience**: Reconstruct from any 7 of 8 pieces
- **Integrity**: CRC32C checksums with early password validation
- **Legacy Support**: Backward compatible with cryptolocker `.encrypted` files
- **Performance**: AVX2/SSE4.2 and BMI2 optimizations when available
- **Portability**: No external dependencies, compiles on Linux, cross-compiles to Windows

## Building

### Linux
```bash
make
```

### Windows (cross-compile from Linux)
```bash
make windows
```

Build requirements:
- g++ with C++17 support
- For Windows: mingw-w64

## Usage

### Encoding (Encrypt and Split)
```bash
phnx example.txt
```
Creates 8 files: `example.txt.phnx_A` through `example.txt.phnx_H`

### Decoding (Reconstruct and Decrypt)
```bash
phnx example.txt.phnx_A
```
Automatically finds other pieces and recreates `example.txt`

Requires at least 7 of 8 pieces to reconstruct.

### Legacy Encryption
```bash
phnx -c example.txt
```
Creates example.txt.encrypted in the older cryptolocker tool format.

### Legacy Decryption
```bash
phnx example.txt.encrypted
```
Decrypts files created by the older cryptolocker tool.

## Password Management

Password can be provided via:
1. Environment variable: `PHNX_PASSWORD=yourpassword phnx file.txt`
2. Interactive prompt (when environment variable not set)

**Security Notes:**
- Minimum 16 characters recommended. No KDF, use long passwords.
- Maximum 32 characters used
- Same password required for encoding and decoding

## How It Works

### Encoding Pipeline
1. Read file in 64KB chunks
2. Calculate CRC32C checksum of plaintext
3. Pad with zeroes to align to 12-byte blocks
4. Encrypt with Speck128/256 in CTR mode using random nonce
5. Append encrypted suffix containing CRC32C (twice), nonce, and plaintext length (without padding or suffix)
6. Apply Golay error correction (doubles data size)
7. Distribute bits across 8 output files

Each output file is ~1/4 the size of the original (doubled by Golay, then divided by 8).

### Decoding Pipeline
1. Find available pieces (need 7 or 8 of 8)
2. Extract and decrypt suffix to get nonce, plaintext length, and expected CRC
3. Validate password early (before full decryption) by comparing the two copies of the CRC in decrypted suffix
4. Stream decode via Golay error correction
5. Decrypt with Speck CTR using extracted nonce
6. Remove zero padding
7. Verify CRC32C matches expected value

### Error Correction

Extended Binary Golay Code (24,12,8):
- Encodes 12 bits of data into 24 bits (12 data + 12 parity)
- Minimum distance of 8 allows correction of up to 3 bit errors
- Each of 8 files contains 3 bits from each 24-bit codeword
- Loss of one entire file = 3 bits per codeword = always correctable
- Can also correct random bit errors within remaining pieces

## File Format

### phnx Format (.phnx_A through .phnx_H)
```
[Golay-encoded encrypted data]
[Golay-encoded encrypted suffix]
```

Suffix (24 bytes=two Golay codewords, encrypted with nonce=-1, counter=-1 and -2):
- Bytes 0-3: CRC32C of plaintext
- Bytes 4-7: CRC32C of plaintext (duplicate for validation)
- Bytes 8-15: Random 64-bit nonce
- Bytes 16-23: Plaintext length (without padding and suffix)

### Legacy cryptolocker Format (.encrypted)
Supported for backward compatibility. See cryptolocker documentation.

## Testing

Run integration tests:
```bash
make test
```

Tests verify:
- Decoding of known good legacy reference files
- Round-trip encoding/decoding
- Resilience with one missing piece

## Return Code

When more than one file has errors, last error is returned.

- 0: Success
- 1: I/O error
- 2: Password mismatch
- 3: Uncorrectable error
- 4: File format error
- 5: Self-test failed

## Security Considerations

### Strengths
- Speck128/256 cipher designed by NSA for embedded systems
- Random nonces prevent keystream reuse
- CRC32C provides integrity checking
- Early password validation (before full decryption)

### Limitations
- CRC32C is not cryptographically secure (use for error detection, not authentication)
- Password strength is critical (recommend 20+ character random passwords)
- No built-in key derivation (passwords used directly as keys)

## Design Rationale

### Why Speck?
- Designed for resource-constrained environments
- Excellent performance without hardware acceleration
- Compact implementation (easier to audit and port)
- Published cryptanalysis

### Why Golay Code?
- Simple, well-understood algorithm
- Efficient encoding/decoding
- No external library dependencies

### Why 8 pieces?
- Golay encodes 12 bits → 24 bits (2× expansion)
- 24 bits ÷ 8 files = 3 bits per file
- Loss of 1 file = 3 bits lost = within Golay correction capability
- More pieces would increase overhead without benefit

## License

MIT license, see LICENSE.txt. Same as cryptolocker and golay components (see individual LICENSE files).

## References

* Encryption/decryption: https://github.com/malobukov/cryptolocker.git
* Golay error correction: https://github.com/notatuta/golay.git
