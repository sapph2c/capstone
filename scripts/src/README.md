# capstone-malware-2025

PE, DLL, and APC Injection (Monolithic and Evasive Dimorphic)

## Installation

Make sure you have the Metasploit Framework installed and Make.

### Environment Variables

Set the Makefile environment variables for the appropriate machine IP addresses, port numbers, and hostname details so that the shellcode XORs properlly at invocation.

```bash
$LHOST: The IP of the listening MSFConsole
$LPORT: The port number of the listening MSFConsole
$HOSTNAME: The hostname of the target machine
```

#### Run the following to generate the .dll payload and .cpp shellcode stubs:

```bash
make generate
```

#### Run to copy the .cpp shellcode stubs into the appropriate paths:

```bash
make copy
```

#### Run to do both in order quickly:

```bash
make all
```

#### Run in order to delete all artifacts:

```bash
make clean
```
