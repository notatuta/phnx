// phnx.cpp
//
// A command-line encryption and error correction tool
//
// Uses Speck128/256 in CTR mode for encryption.
//
// Last six bytes of Golay encoded files contain 24 byte suffix (two 12 byte blocks),
// encrypted the same way with nonce -1 and counter -1 and -2, distributed across 
// the eight slices. Suffix bytes contain the following:
//
//     Bytes 0-3: CRC32C of plaintext
//     Bytes 4-7: CRC32C of plaintext (second copy)
//     Bytes 8-15: nonce randomly generated during encryption
//     Bytes 16-23: plaintext length (same as ciphertext length)
//
// In legacy single-file mode, a 16 byte long suffix is appended at the end of the file, 
// encrypted with CTR the same way with nonce -1 and counter -1.
// Suffix bytes contain the following:
//
//     Bytes 0-3: CRC32C of plaintext
//     Bytes 4-7: CRC32C of plaintext (second copy)
//     Bytes 8-15: nonce randomly generated during encryption
//
// Older versions used file length as nonce, and kept checksum in filename.
// This can potentially be a problem, as encrypting two files of the same size with the same 
// key leaks their XOR. Decryption code for this approach is kept for backwards compatibility,
// but encryption is now always using random nonces.
//
// Byte order and test vectors as in Speck implementation guide 
// https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
//
// Building:
//
//   g++ -O3 -Wall -Wextra -std=c++17 -march=native -g -o phnx phnx.cpp
//
// To cross-compile Windows executable on Linux, install MinGW-w64:
//
//   sudo apt-get install mingw-w64
//
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctype.h>
#include <fstream> 
#include <iostream>
#include <memory>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <x86intrin.h>
#include <limits.h>
#include <random>
#include <inttypes.h>

#define PHNX_VERSION "4.0.2"

enum PHNX_ERROR_CODE {
  PHNX_OK = 0,
  PHNX_IO_ERROR,
  PHNX_WRONG_PASSWORD,
  PHNX_UNCORRECTABLE_ERROR,
  PHNX_FORMAT_ERROR,
  PHNX_SELF_TEST_FAILED
};

class GolayCode {
  public:
    int processed_codewords_ = 0;
    int corrected_codewords_ = 0;
    int uncorrectable_codewords_ = 0;

    // Takes 12 bits of data, appends 12 checksum bits, returns a 24 bit codeword
    unsigned inline encode(unsigned x) const
    {
      return ((x & 0xfff) << 12) | checksum_bits(x);
    }

    // Takes a 24 bit codeword, returns decoded 12 bits.
    // On unrecoverable error, returns -1.
    int decode(unsigned x)
    {
      processed_codewords_++;

      unsigned received_data = (x >> 12) & 0xfff;
      unsigned received_checksum = x & 0xfff;
      unsigned expected_checksum = checksum_bits(received_data);

      // Which checksum bits differ between what we expected and what we received 
      unsigned syndrome = expected_checksum ^ received_checksum;

      // Number of checksum bits that differ between what we expected and what we received 
      int weight = __builtin_popcount(syndrome);

      // When there are three or fewer errors in the checksum bits, then either there are no errors
      // in the data bits (and no correction is necessary), or there are at least 5 errors in the 
      // data bits (and we can't correct that many errors anyway, so return data bits as they are).
      if (weight <= 3) {
        if (weight) {
          corrected_codewords_++;  
        }
        return received_data;
      }

      // To find exactly one error in the data bits, flip each bit in turn and see if an error in 
      // that bit gets us within two bits of the received checksum. More errors would give a total 
      // error weight of 4 or more, which would be uncorrectable.
      for (int i = 0; i < 12; i++) {
        unsigned error_mask = 1 << (11 - i);
        unsigned coding_error = golay_matrix_[i];
        if (__builtin_popcount(syndrome ^ coding_error) <= 2) {
          corrected_codewords_++;
          return received_data ^ error_mask;
        }
      }

      // Check whether all (up to three) errors are in the data bits
      unsigned inverted_syndrome = checksum_bits(syndrome);
      int w = __builtin_popcount(inverted_syndrome);
      if (w <= 3) {
        corrected_codewords_++;
        return received_data ^ inverted_syndrome;
      }

      // Finally, try to find two errors in the data bits and one in the checksum bits
      for (int i = 0; i < 12; i++) {
        unsigned coding_error = golay_matrix_[i];
        if (__builtin_popcount(inverted_syndrome ^ coding_error) <= 2) {
          corrected_codewords_++;
          return received_data ^ inverted_syndrome ^ coding_error;
        }
      }

      // Give up
      uncorrectable_codewords_++;
      return -1;
    }

  private:
    static constexpr unsigned const golay_matrix_[] = {
      0x9f1, 0x4fa, 0x27d, 0x93e, 0xc9d, 0xe4e,
      0xf25, 0xf92, 0x7c9, 0x3e6, 0x557, 0xaab
    };

    unsigned inline checksum_bits(unsigned x) const
    {
      unsigned y = 0;
      for (int i = 0; i < 12; i++) {
        y = (y << 1) | __builtin_parity(x & golay_matrix_[i]);
      }
      return y;
    }
};

static inline void
speck_round(uint64_t& x, uint64_t& y, const uint64_t k)
{
  #if defined(__AVX2__)
    x = __rorq(x, 8);
  #else
    x = (x >> 8) | (x << (64 - 8));
  #endif
  x += y;
  x ^= k;
  #if defined(__AVX2__)
    y = __rolq(y, 3);
  #else
    y = (y << 3) | (y >> (64 - 3));
  #endif
  y ^= x;
}

static void 
speck_schedule( const uint64_t key[4]
              , uint64_t schedule[34]
              )
{
  uint64_t a = key[0];
  uint64_t bcd[3] = {key[1], key[2], key[3]};
  for (unsigned i = 0; i < 33; i++) {
    schedule[i] = a; 
    speck_round(bcd[i % 3], a, i);
  }
  schedule[33] = a; 
}

static void 
speck_encrypt( const uint64_t plaintext[2]
             , const uint64_t schedule[34]
             , uint64_t ciphertext[2]
             )
{
  ciphertext[0] = plaintext[0];
  ciphertext[1] = plaintext[1];
  for (unsigned i = 0; i < 34; i++) {
    speck_round(ciphertext[1], ciphertext[0], schedule[i]); 
  }
}

static void 
speck_encrypt4( const uint64_t plaintext[2 * 4]
              , const uint64_t schedule[34]
              , uint64_t ciphertext[2 * 4]
              )
{
  #if defined(__AVX2__)
    auto x = _mm256_set_epi64x(plaintext[7], plaintext[6], plaintext[5], plaintext[4]);
    auto y = _mm256_set_epi64x(plaintext[3], plaintext[2], plaintext[1], plaintext[0]);
    for (unsigned i = 0; i < 34; i++) {
      auto si = schedule[i];
      x = _mm256_or_si256(_mm256_srli_epi64(x, 8), _mm256_slli_epi64(x, 64 - 8)); // rotate x right by 8
      x = _mm256_add_epi64(x, y);
      x = _mm256_xor_si256(x, _mm256_set_epi64x(si, si, si, si));
      y = _mm256_or_si256(_mm256_slli_epi64(y, 3), _mm256_srli_epi64(y, 64 - 3)); // rotate y left by 3
      y = _mm256_xor_si256(y, x);
    }
    _mm256_storeu_si256((__m256i_u*)&ciphertext[4], x);
    _mm256_storeu_si256((__m256i_u*)&ciphertext[0], y);
  #else
    ciphertext[0] = plaintext[0]; ciphertext[1] = plaintext[1];
    ciphertext[2] = plaintext[2]; ciphertext[3] = plaintext[3];
    ciphertext[4] = plaintext[4]; ciphertext[5] = plaintext[5];
    ciphertext[6] = plaintext[6]; ciphertext[7] = plaintext[7];
    for (unsigned i = 0; i < 34; i++) {
      auto si = schedule[i];
      speck_round(ciphertext[4], ciphertext[0], si); 
      speck_round(ciphertext[5], ciphertext[1], si); 
      speck_round(ciphertext[6], ciphertext[2], si); 
      speck_round(ciphertext[7], ciphertext[3], si); 
    }
  #endif
}

static uint64_t 
bytes_to_uint64(const uint8_t bytes[], unsigned length)
{
  uint64_t w = 0;
  for (unsigned i = 0, shift = 0; i < length; i++, shift += 8) {
    w |= ((uint64_t)bytes[i] << shift);
  }
  return w;
}

union EightTriplets {
  uint8_t bytes[8][3];
  uint64_t qwords[3];  
};

// Can write to buffer past bytes_to_read to include the complete last 12 byte word 
static int golay_read_and_decode(uint8_t* buffer, size_t bytes_to_read, std::fstream slices[8], GolayCode& gc)
{
  // Read from each available slice
  auto bytes_to_read_from_each_chunk = (bytes_to_read + 3) / 4; // Round up for partial
  std::unique_ptr<char[]> slice_chunks[8];
  for (int i = 0; i < 8; i++) {
    slice_chunks[i] = std::make_unique<char[]>(bytes_to_read_from_each_chunk); // Bytes not read set to zero
    if (slices[i].is_open()) {
      slices[i].read(slice_chunks[i].get(), bytes_to_read_from_each_chunk);
      if (!slices[i]) {
        std::cerr << "\nError reading from slice " << (char)('A' + i) << "\n";
        return PHNX_IO_ERROR;
      }
    }
  }

  for (size_t block_offset = 0; block_offset < bytes_to_read; block_offset += 12) {
    // Copy 3 bytes from each slice
    EightTriplets eighttriplets = {};
    for (int i = 0; i < 8; i++) {
      memcpy(&eighttriplets.bytes[i][0], slice_chunks[i].get() + block_offset / 4, 3);
    }

    // Reconstruct via Golay decode
    union {
      uint8_t bytes[12];
      uint64_t qwords[2];
    } twelvebytes = {};
    for (int i = 0; i < 8; i++) {
      #if defined(__BMI2__)
        const uint64_t mask = 0x0101010101010101ULL << i;
        const uint64_t halfmask = mask & 0xffffffff;
        const uint64_t extracted_lo  = _pext_u64(eighttriplets.qwords[0], mask);
        const uint64_t extracted_mid = _pext_u64(eighttriplets.qwords[1], mask);
        const uint64_t extracted_hi  = _pext_u64(eighttriplets.qwords[2], mask);
        const int codeword = (int)(extracted_lo | (extracted_mid << 8) | (extracted_hi << 16));
      #else
        int codeword = 0;
        for (int k = 0; k < 8; k++) {
          for (int t = 0; t < 3; t++) {
            if (eighttriplets.bytes[k][t] & (1 << i)) {
              codeword |= (1 << (k * 3 + t));
            }
          }
        }
      #endif
      const int x = gc.decode(codeword); // Do not stop on uncorrectable errors, report them at the end
      #if defined(__BMI2__)
        twelvebytes.qwords[0] |= _pdep_u64(x, mask);
        twelvebytes.qwords[1] |= _pdep_u64(x >> 8, halfmask);
      #else
        for (int j = 0; j < 12; j++) {
          if (x & (1 << j)) {
            twelvebytes.bytes[j] |= (1 << i);
          }
        }
      #endif
    }

    // Copy to buffer
    memcpy(buffer + block_offset, twelvebytes.bytes, 12);
  }
  return PHNX_OK;
}

static int golay_encode_and_write(const uint8_t* data, size_t data_size, std::fstream slices[8], GolayCode& gc)
{
  const auto bytes_to_write_to_each_chunk = (data_size + 3) / 4; // Round up for partial
  std::unique_ptr<char[]> slice_chunks[8];
  for (int i = 0; i < 8; i++) {
    slice_chunks[i] = std::make_unique<char[]>(bytes_to_write_to_each_chunk);
  }

  for (size_t block_offset = 0; block_offset < data_size; block_offset += 12) {

    // Pad with zeroes
    union {
      uint8_t bytes[12];
      uint64_t qwords[2];
    } twelvebytes = {};
    size_t copy_size = std::min((size_t)12, data_size - block_offset);
    memcpy(&twelvebytes.bytes[0], data + block_offset, copy_size);

    // Rearrange into eight slices, each three byte long
    EightTriplets eighttriplets = {};
    for (int i = 0; i < 8; i++) {
      #if defined(__BMI2__)
        const uint64_t mask = 0x0101010101010101ULL << i;
        const uint64_t halfmask = mask & 0xffffffff;
        auto bits0to7  = _pext_u64(twelvebytes.qwords[0], mask);
        auto bits8to11 = _pext_u64(twelvebytes.qwords[1], halfmask);
        const int x = (int)(bits0to7 | (bits8to11 << 8));
      #else
        int x = 0;
        for (int j = 0; j < 12; j++) {
          if (twelvebytes.bytes[j] & (1 << i)) {
            x |= (1 << j);
          }
        }
      #endif
      const int codeword = gc.encode(x);
      #if defined(__BMI2__)
        eighttriplets.qwords[0] |= _pdep_u64((codeword      ) & 0xff, mask);
        eighttriplets.qwords[1] |= _pdep_u64((codeword >>  8) & 0xff, mask);
        eighttriplets.qwords[2] |= _pdep_u64((codeword >> 16) & 0xff, mask);
      #else
        for (int k = 0; k < 8; k++) {
          for (int t = 0; t < 3; t++) {
            if (codeword & (1 << (k * 3 + t))) {
              eighttriplets.bytes[k][t] |= (1 << i);
            }
          }
        }
      #endif
    }

    // Copy 3 bytes to each slice
    for (int i = 0; i < 8; i++) {
      memcpy(slice_chunks[i].get() + block_offset / 4, &eighttriplets.bytes[i][0], 3);
    }
  }

  // Write all slices
  for (int i = 0; i < 8; i++) {
    slices[i].write(slice_chunks[i].get(), bytes_to_write_to_each_chunk);
    if (!slices[i]) {
      std::cerr << "\nError writing slice" << ('A' + i) << "\n";
      return PHNX_IO_ERROR;
    }
  }
  return PHNX_OK;
}

static int
process_one_file(const char* filename, const uint64_t schedule[34], bool compatibility_mode)
{
  // If filename ends with ".encrypted", CRC32C (twice) and nonce are appended at the end of the file
  // If filename ends with ".encrypted-XXXXXXXX", where XXXXXXXX are hexadecimal digits, 
  // then XXXXXXXX is checksum, and file length is nonce (for compatibility with previous version)
  // If filename ends with ".phnx_A" then it's the first slice of Golay encoded data
  bool check_checksum = false;
  uint32_t expected_checksum = 0;
  bool check_crc32c = false;
  uint32_t expected_crc32c = 0;
  bool append_suffix = true;
  uint64_t nonce = 0;
  bool golay_encode = !compatibility_mode;
  bool golay_decode = false;
  std::fstream f;
  std::streamsize buffer_size = 1024 * 1024;
  auto buffer = std::make_unique<char[]>(buffer_size);
  f.rdbuf()->pubsetbuf(buffer.get(), buffer_size);
  std::fstream slices[8];
  std::unique_ptr<char[]> slices_buffer[8];
  for (int i = 0; i < 8; i++) {
    slices_buffer[i] = std::make_unique<char[]>(buffer_size);
  }
  long length = 0;
  long remaining_length = 0;
  GolayCode gc;

  const char* p = filename;
  if (!*p) {
    std::cerr << "Empty filename\n";
    return PHNX_IO_ERROR;
  } 
  while (*p) {
    p++; 
  }
  p--; // p points to last character in filename
  if (p - 6 > filename) { // p - 6 points to '.' in ".phnx_A'
    if ( strncmp(p - 6, ".phnx_A", 7) == 0
      || strncmp(p - 6, ".phnx_B", 7) == 0
      || strncmp(p - 6, ".phnx_C", 7) == 0
      || strncmp(p - 6, ".phnx_D", 7) == 0
      || strncmp(p - 6, ".phnx_E", 7) == 0
      || strncmp(p - 6, ".phnx_F", 7) == 0
      || strncmp(p - 6, ".phnx_G", 7) == 0
      || strncmp(p - 6, ".phnx_H", 7) == 0
       ) {
      int missing_ct = 0;
      for (int i = 0; i < 8; i++) {
        auto slice_filename = std::string(filename);
        slice_filename.back() = 'A' + i;
        slices[i].open(slice_filename, std::fstream::in | std::fstream::binary);
        if (!slices[i].is_open()) {
          std::cerr << "Cannot open " << slice_filename << "\n";
          if (missing_ct) {
            std::cerr << "More than one slice is missing, not enough to recover\n";
            return PHNX_UNCORRECTABLE_ERROR;
          }
          missing_ct++;
        }
      }
      golay_decode = true;
      golay_encode = false;
      check_crc32c = true;
      append_suffix = false;
    }    
    if (golay_decode) {
      auto filename_start = std::string(filename);
      filename_start.back() = '[';
      std::cout << "Processing " << filename_start << "A-H]\n";
    } else {
      std::cout << "Processing " << filename << "\n";
    }
  }
  if (p - 9 > filename) { // p - 9 points to '.' in ".encrypted'
    if (strncmp(p - 9, ".encrypted", 10) == 0) {
      check_crc32c = true;
      append_suffix = false;
      golay_encode = false;
    } else {
      // Check if filename contains checksum from old version
      while (p > filename && isxdigit(*p)) p--; // p points to '-'
      if (p - 11 > filename) {
        if (strncmp(p - 10, ".encrypted-", 11) == 0) {
          size_t expected_checksum_length = 0;
          expected_checksum = std::stoul(p + 1, &expected_checksum_length, 16);
          if (expected_checksum_length > 0) {
            check_checksum = true;
            append_suffix = false;
            golay_encode = false;
          }
        }
      }
    }
  }

  if (golay_decode) {

    // Read suffix (2 blocks = 48 bytes = 6 bytes per slice)
    for (int i = 0; i < 8; i++) {
      slices[i].seekg(-6, std::ios::end);
    }
    uint8_t suffix_bytes[24] = {};
    auto ret = golay_read_and_decode(suffix_bytes, 24, slices, gc);
    if (ret) {
      return ret;
    }
    for (int i = 0; i < 8; i++) {
      slices[i].seekg(0);
    }

    // Extracted suffix. TODO: consider std::bit_cast to avoid relying on machine's endianess
    uint64_t suffix[3];
    memcpy(suffix, suffix_bytes, 24);

    // Decrypt suffix with nonce=-1 and counter=-1, -2
    const uint64_t nonce_and_ctr_minus1[2] = { 0xffffffffffffffffULL, 0xffffffffffffffffULL };
    const uint64_t nonce_and_ctr_minus2[2] = { 0xffffffffffffffffULL, 0xfffffffffffffffeULL };
    uint64_t gamma[2];
    speck_encrypt(nonce_and_ctr_minus1, schedule, gamma);
    suffix[0] ^= gamma[0];
    suffix[1] ^= gamma[1];
    speck_encrypt(nonce_and_ctr_minus2, schedule, gamma);
    suffix[2] ^= gamma[0];

    // Validate: check if two CRC32C copies match
    const uint32_t crc32c0 = (uint32_t)suffix[0];
    const uint32_t crc32c1 = (uint32_t)(suffix[0] >> 32);
    if (crc32c0 != crc32c1) {
      std::cerr << "CRC mismatch, wrong password?\n";
      return PHNX_WRONG_PASSWORD;
    }
    check_crc32c = true;
    expected_crc32c = crc32c0;
    nonce = suffix[1];
    length = suffix[2];
    remaining_length = length;

    // Trim ".phnx_A" at the end
    auto base_filename = std::string(filename).substr(0, strlen(filename) - 7);
    f.open(base_filename, std::fstream::out | std::fstream::binary);
    if (!f) {
      std::cerr << "Cannot create " << base_filename << "\n";
      return PHNX_IO_ERROR;
    }
  } else {
    if (golay_encode) {
      f.open(filename, std::fstream::in | std::fstream::binary);
    } else {
      f.open(filename, std::fstream::in | std::fstream::out | std::fstream::binary);
    } 
    if (!f) {
      std::cerr << "Cannot open " << filename << "\n";
      return PHNX_IO_ERROR;
    }
    // Determmine file length
    const auto begin = f.tellg();
    f.seekg(0, std::ios::end);
    const auto end = f.tellg();
    f.seekg(0, std::ios::beg);
    length = (end - begin);
    remaining_length = length;
    nonce = (uint64_t)length;

    if (check_crc32c & !golay_decode) {
      if (length < 16) {
        std::cerr << "\nNo suffix in " << filename << "\n";
        return PHNX_FORMAT_ERROR;
      }
      // Read the suffix
      f.seekg(length - 16);
      uint64_t suffix[2] = {};
      f.read((char*)(&suffix[0]), 16);
      if (!f) {
        std::cerr << "\nError reading suffix from " << filename << "\n";
        return PHNX_IO_ERROR;
      }
      f.seekg(0);

      // Decrypt suffix on nonce -1 and counter -1
      const uint64_t all_ones[2]  = { 0xffffffffffffffffULL, 0xffffffffffffffffULL };
      uint64_t gamma[2];
      speck_encrypt(all_ones, schedule, gamma);
      suffix[0] ^= gamma[0];
      suffix[1] ^= gamma[1];

      // See if the two copies of the checksum stored in the suffix match
      const uint32_t crc32c0 = (uint32_t)suffix[0];
      const uint32_t crc32c1 = (uint32_t)(suffix[0] >> 32);
      if (crc32c0 != crc32c1) {
        std::cerr << "CRC mismatch, maybe wrong password?\n";
        return PHNX_WRONG_PASSWORD;
      }
      expected_crc32c = crc32c0;
      nonce = suffix[1];
      remaining_length = length - 16;
    }
  }
  if (append_suffix || golay_encode) { 
    long long unsigned int random_number = 
      std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
      ).count(); // If no hardware random number generator is available, use time as a substitute
    #if defined(__AVX2__)
      _rdrand64_step(&random_number); // Use hardware random number generator, if available, to create nonce
    #endif
    nonce ^= (uint64_t)random_number;
  }

  // Make progress bar length proportional to log of file size, plus intercept
  unsigned total_notches = 10;
  {
    auto x = remaining_length;
    while (x >>= 1) total_notches++;
  }
  std::cerr << " ";
  for (unsigned i = 0; i < total_notches; i++) {
    std::cerr << ".";
  }
  std::cerr << " \r ";
  unsigned notches_shown = 0;

  uint64_t nonce_and_counter[2 * 4] = { 
    nonce, nonce, nonce, nonce, 
    0, 1, 2, 3};

  // Use CRC-32C (Castagnoli) for checksum
  uint32_t crc32c_before = ~0U;
  uint32_t crc32c_after = ~0U;
  #if !defined(__AVX2__)
    unsigned crc32c_table[256] = {};
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t j = i;
      for (int k = 0; k < 8; k++) {
        j = j & 1 ? (j >> 1) ^ 0x82f63b78 : j >> 1;
      }
      crc32c_table[i] = j;
    }
  #endif

  if (golay_encode) {
    for (int i = 0; i < 8; i++) {
      auto slice_filename = std::string(filename);
      slice_filename.append(".phnx_");
      slice_filename.push_back('A' + i);
      slices[i].open(slice_filename, std::ios::out | std::ios::trunc);
      if (!slices[i]) {
        std::cerr << "Cannot create " << slice_filename << "\n";
        return PHNX_IO_ERROR;
      }
    }
  }

  while (remaining_length) {

    uint8_t buffer[16 * 4 * 12 * 100]; // Should be divisible by 12 (for Golay) and by 16 * 4 (for Speck)
    std::uintmax_t chunk_size = remaining_length;
    if (chunk_size > sizeof(buffer)) {
      chunk_size = sizeof(buffer);
    }

    if (golay_decode) {
      auto ret = golay_read_and_decode(buffer, chunk_size, slices, gc);
      if (ret) {
        return ret;
      }
    } else {
      // Remember current position, read next chunk, move file pointer back
      auto position = f.tellg();
      f.read((char*)(&buffer[0]), chunk_size);
      if (!f) {
        std::cerr << "\nError reading " << filename << "\n";
        for (int i = 0; i < 8; i++) slices[i].close();
        return PHNX_IO_ERROR;
      }
      if (!golay_encode) {
        f.seekg(position);
      }
    }

    // Update CRC32C before processing
    for (unsigned offset = 0; offset < chunk_size; offset++) {
      #if defined(__AVX2__)
        crc32c_before = _mm_crc32_u8(crc32c_before, buffer[offset]);
      #else
        crc32c_before = crc32c_table[(crc32c_before ^ buffer[offset]) & 0xff] ^ (crc32c_before >> 8);
      #endif
    }

    for (unsigned offset = 0; offset < chunk_size; offset += 16 * 4) {

      // Get more of the keystream
      uint64_t keystream[2 * 4];
      speck_encrypt4(nonce_and_counter, schedule, keystream);
      nonce_and_counter[4] += 4;
      nonce_and_counter[5] += 4;
      nonce_and_counter[6] += 4;
      nonce_and_counter[7] += 4;

      // XOR buffer with keystream
      // Same byte order as in Words64ToBytes() from implementation guide
      for (unsigned i = 0; i < 8; i++) {
        buffer[offset + i + 0 * 8] ^= keystream[0] >> (i * 8);
        buffer[offset + i + 1 * 8] ^= keystream[4] >> (i * 8);
        buffer[offset + i + 2 * 8] ^= keystream[1] >> (i * 8);
        buffer[offset + i + 3 * 8] ^= keystream[5] >> (i * 8);
        buffer[offset + i + 4 * 8] ^= keystream[2] >> (i * 8);
        buffer[offset + i + 5 * 8] ^= keystream[6] >> (i * 8);
        buffer[offset + i + 6 * 8] ^= keystream[3] >> (i * 8);
        buffer[offset + i + 7 * 8] ^= keystream[7] >> (i * 8);
      }
    }

    // Update CRC32C after processing
    for (unsigned offset = 0; offset < chunk_size; offset++) {
      #if defined(__AVX2__)
        crc32c_after = _mm_crc32_u8(crc32c_after, buffer[offset]);
      #else
        crc32c_after = crc32c_table[(crc32c_after ^ buffer[offset]) & 0xff] ^ (crc32c_after >> 8);
      #endif
    }

    if (golay_encode) {
      auto ret = golay_encode_and_write(&buffer[0], chunk_size, slices, gc);
      if (ret) {
        return ret;
      }
    } else {
      // Write processed buffer back
      f.write((char*)(&buffer[0]), chunk_size);
      if (!f) {
        std::cerr << "\nError writing " << filename << "\n";
        return PHNX_IO_ERROR;
      }
    }
    remaining_length -= chunk_size;

    // Update progress bar if needed 
    auto notches_remaining = total_notches - (unsigned)(((double)length - remaining_length) * total_notches / length);
    if (total_notches - notches_shown > notches_remaining) {
      auto notches_to_show = total_notches - notches_shown - notches_remaining;
      while (notches_to_show--) {
        std::cerr << "o";
        notches_shown++;
      }
    }
  }
  std::cerr << "\r ";
  for (unsigned i = 0; i < total_notches; i++) {
    std::cerr << ' ';
  }
  std::cerr << " \r";
  crc32c_before = ~crc32c_before;
  crc32c_after = ~crc32c_after;
  if (golay_encode) {
    uint64_t suffix[3] = { 
      (((uint64_t)crc32c_before) << 32) | (uint64_t)crc32c_before, 
      nonce,
      (uint64_t)length
    };

    // Encrypt suffix with nonce=-1 and counter=-1, -2
    const uint64_t nonce_and_ctr_minus1[2] = { 0xffffffffffffffffULL, 0xffffffffffffffffULL };
    const uint64_t nonce_and_ctr_minus2[2] = { 0xffffffffffffffffULL, 0xfffffffffffffffeULL };
    uint64_t gamma[2];
    speck_encrypt(nonce_and_ctr_minus1, schedule, gamma);
    suffix[0] ^= gamma[0];
    suffix[1] ^= gamma[1];
    speck_encrypt(nonce_and_ctr_minus2, schedule, gamma);
    suffix[2] ^= gamma[0];

    // TODO: consider std::bit_cast to avoid relying on machine's endianess
    uint8_t suffix_bytes[24];
    memcpy(suffix_bytes, suffix, 24);

    auto ret = golay_encode_and_write(suffix_bytes, 24, slices, gc);
    if (ret) {
      return ret;
    }

    for (int i = 0; i < 8; i++) slices[i].close();

    return PHNX_OK;
  } else if (append_suffix) {
    uint64_t suffix[2] = { (((uint64_t)crc32c_before) << 32) | (uint64_t)crc32c_before, nonce };
    // Encrypt suffix on nonce = counter = -1
    const uint64_t all_ones[2]  = { 0xffffffffffffffffULL, 0xffffffffffffffffULL };
    uint64_t gamma[2];
    speck_encrypt(all_ones, schedule, gamma);
    suffix[0] ^= gamma[0];
    suffix[1] ^= gamma[1];
    f.write((char*)(&suffix[0]), 16);
    if (!f) {
      std::cerr << "\nError writing suffix\n";
      return PHNX_IO_ERROR;
    }
    f.close();
    std::string new_filename(filename);
    new_filename.append(".encrypted");
    if (rename(filename, new_filename.c_str())) {
      std::cerr << "Error renaming " << filename << " to " << new_filename << "\n";
      return PHNX_IO_ERROR;  
    }
    return PHNX_OK;
  }
  f.close();
  if (check_checksum) {
    // Legacy checksum from plainext CRC32C, ciphertext CRC32C, and file length
    uint64_t checksum_in[2];
    // Upper: ciphertext CRC32C (before decryption). Lower: plaintext CRC32C (after decryption) 
    checksum_in[0] = (((uint64_t)crc32c_before) << 32) | (uint64_t)crc32c_after;
    checksum_in[1] = (uint64_t)length;
    // Encrypt on the same key
    uint64_t checksum_out[2];
    speck_encrypt(checksum_in, schedule, checksum_out);
    // Take the lowest 32 bits
    uint32_t checksum = (uint32_t)(checksum_out[0]);

    if (checksum != expected_checksum) {
      std::cerr << "Checksum mismatch: expected 0x" << std::hex << expected_checksum << ", got 0x" << checksum << "\n";  
      return PHNX_FORMAT_ERROR;
    } else {
      std::string new_filename(filename);
      new_filename = new_filename.substr(0, p - 10 - filename);
      if (rename(filename, new_filename.c_str())) {
        std::cerr << "Error renaming " << filename << " to " << new_filename << "\n";
        return PHNX_IO_ERROR;  
      }
      return PHNX_OK;
    }
  }
  if (check_crc32c) {
    if (expected_crc32c != crc32c_after) {
      std::cerr << "CRC32C mismatch: expected 0x" << std::hex << expected_crc32c << ", got 0x" << crc32c_after << "\n";  
      return PHNX_FORMAT_ERROR;      
    } else if (!golay_decode) { 
      std::string new_filename(filename);
      new_filename = new_filename.substr(0, p - 9 - filename);
      if (rename(filename, new_filename.c_str())) {
        std::cerr << "Error renaming " << filename << " to " << new_filename << "\n";
        return PHNX_IO_ERROR;  
      } 
      if (truncate(new_filename.c_str(), length - 16)) {
        std::cerr << "Error truncating " << new_filename << "\n";
        return PHNX_IO_ERROR;
      }
    }
  }
  if (golay_decode) {
    if (gc.corrected_codewords_ || gc.uncorrectable_codewords_) {
      std::cerr << "Processed " << gc.processed_codewords_ << " Golay codewords, " 
                << "corrected " << gc.corrected_codewords_ << ", "
                << gc.uncorrectable_codewords_ << " uncorrectable\n";
    }
    if (gc.uncorrectable_codewords_) {
      return PHNX_UNCORRECTABLE_ERROR;
    }
  }
  return PHNX_OK;
}

int main(int argc, char** argv)
{
  // When called without filename(s), run self-test and show usage
  if (argc <= 1) {
    //
    // Speck test vectors from the paper
    //
    const uint64_t key[4]       = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL
                                  , 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL };
    const uint64_t plaintext[2] = { 0x202e72656e6f6f70ULL, 0x65736f6874206e49ULL };
    const uint64_t expected[2]  = { 0x4eeeb48d9c188f43ULL, 0x4109010405c0f53eULL };
    uint64_t schedule[34];
    speck_schedule(key, schedule);
    uint64_t observed[2];
    speck_encrypt(plaintext, schedule, observed);
    if ( expected[0] != observed[0] 
      || expected[1] != observed[1]
       ) {
      std::cerr << "speck_encrypt() self-test failed\n" 
                << "Expected 0x" << std::hex << expected[0] << ", 0x" << expected[1] << "\n"
                << "Observed 0x" << observed[0] << ", 0x" << observed[1] << "\n";
       return PHNX_SELF_TEST_FAILED;
    }
    const uint64_t converted[2] =  { bytes_to_uint64((uint8_t*)"pooner. ", 8)
                                   , bytes_to_uint64((uint8_t*)"In those", 8)};
    if ( plaintext[0] != converted[0] 
      || plaintext[1] != converted[1]
       ) {
      std::cerr << "bytes_to_uint64() self-test failed\n" 
                << "Expected 0x" << std::hex << plaintext[0] << ", 0x" << plaintext[1] << "\n"
                << "Observed 0x" << converted[0] << ", 0x" << converted[1] << "\n";
       return PHNX_SELF_TEST_FAILED;
    }

    //
    // Golay code self-test: encode some random 12-bit words, add errors, count
    // how many errors are corrected or detected
    //
    GolayCode gc;
    unsigned not_decoded_ct[11] = {};
    unsigned decoded_ok_ct[11] = {};
    unsigned decoded_wrong_ct[11] = {};
    for (int i = 0; i < 10000; i++) {
      for (int j = 0; j < 11; j++) {
        unsigned x = rand() & 0xfff;
        auto y = gc.encode(x);
        unsigned errors = 0;
        for (int k = 0; k < j; ) {
          unsigned bit = 1 << (rand() % 24);
          if ((errors & bit) == 0) {
            errors |= bit;
            k++;
          }
        }
        auto z = gc.decode(y ^ errors);
        if (z < 0) {
          not_decoded_ct[j]++;
        } else if ((unsigned)z == x) {
          decoded_ok_ct[j]++;
        } else {
          decoded_wrong_ct[j]++;
        }
        if ((unsigned)z != x && j < 4) {
          std::cerr << "GolayCode self-test failed\n"
                    << "Original:    0x" << std::hex << x << "\n"
                    << "Transmitted: 0x" << y  << "\n"
                    << "Error bits:  0x" << errors  << "\n"
                    << "Received:    0x" << (y ^ errors) << std::dec << "\n"; 
          if (z < 0) {
            std::cerr << "Nothing decoded\n";
          } else {
            std::cerr << "Decoded:     0x" << std::hex << z << std::dec << "\n";
          }
          return PHNX_SELF_TEST_FAILED;
        }
      }
    }
  	std::cerr << "phnx version " PHNX_VERSION "\n\n"
      "Usage:\n\n\t" << argv[0] << " [-c] file1 [-g] [file2] [...]\n\n"
  	  "Encrypt a given file or files, add error correction bits, split into eight slices.\n"
      "When given a slice, read all eight slices, correct errors if possible, then decrypt the original file.\n"
      "Option -c turns on compatibility mode (encryption only, no error correction) for the files that follow,\n"
      "option -g turns it off. Password can be passed via environment variable PHNX_PASSWORD.\n";
    #if defined(__AVX2__) && defined (__BMI2__)
      std::cerr << "Will use SSE4.2, AVX2, and BMI instructions.\n";
    #elif defined(__AVX2__)
      std::cerr << "Will use SSE4.2 and AVX2 instructions.\n";
    #elif defined(__BMI2__)
      std::cerr << "Will use BMI2 instructions.\n";
    #endif
  	return PHNX_OK;
  }

  std::string first_attempt;
  const char* password = std::getenv("PHNX_PASSWORD");
  if (!password) {
    std::cerr << "Enter encryption key (32 chars max): ";
    std::getline (std::cin, first_attempt);
    std::cerr << "Enter encryption key again         : ";
    std::string second_attempt;
    std::getline (std::cin, second_attempt);
    if (first_attempt.compare(second_attempt) != 0) {
      std::cerr << "Keys don't match\n";
      return PHNX_WRONG_PASSWORD;
    }
    password = first_attempt.c_str();
  } else {
    std::cerr << "Using password from environment variable\n";
  }

  // Convert password to four little-endian 64-bit words, zero padded,
  // as in BytesToWords64() from implementation guide 
  uint64_t k[4] = {0};
  unsigned bytes_left = strlen(password);
  if (bytes_left < 16) {
    std::cerr << "WARNING: password is less than 16 characters long\n";
  } else if (bytes_left > 32) {
    std::cerr << "WARNING: password is longer than 32 characters, only using the first 32\n";
  }
  for (unsigned i = 0; i < 4; i++, bytes_left -= 8) {
    k[i] = bytes_to_uint64((uint8_t*)(password + i * 8), bytes_left > 8 ? 8 : bytes_left);
    if (bytes_left <= 8) break;
  }

  // Prepare key schedule
  uint64_t schedule[34];
  speck_schedule(k, schedule);

  // Iterate over the given files (can be more than one)
  unsigned ok_ct = 0, fail_ct = 0;
  bool compatibility_mode = false;
  int last_error_code = PHNX_OK;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0) {
      compatibility_mode = true;
      continue;
    }
    if (strcmp(argv[i], "-g") == 0) {
      compatibility_mode = false;
      continue;
    }
    auto result = process_one_file(argv[i], schedule, compatibility_mode);
    if (result) {
      last_error_code = result;
      fail_ct++;
    } else {
      ok_ct++;
    }
  }
  if (ok_ct + fail_ct > 1) {
    std::cerr << (ok_ct + fail_ct) << " files, " << fail_ct << " errors\n";
  }
  return last_error_code;
}
