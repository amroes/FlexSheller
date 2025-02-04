# FlexSheller
Made by @amroes

FlexSheller is a versatile tool for generating various types of shellcode in different formats, making it easy to adapt to various use cases. The tool supports modes that allow you to generate the shellcode as MAC addresses, IP addresses, UUIDs, and different encryption formats.

## Usage

```bash
FlexSheller <mode> <payload_file> [key] [-o <output_file>]
```
## Modes:
-----------------------------------------------------------------------------------------------------
### "mac"
Output the shellcode as an array of MAC addresses.
Example: FC-48-83-E4-F0-E8

### "ipv4"
Output the shellcode as an array of IPv4 addresses.
Example: 252.72.131.228

### "ipv6"
Output the shellcode as an array of IPv6 addresses.
Example: FC48:83E4:F0E8:C000:0000:4151:4150:5251

### "uuid"
Output the shellcode as an array of UUID strings.
Example: FC4883E4-F0E8-C000-0000-415141505251

### "aes"
Output the shellcode as an array of AES encrypted shellcode with a random key and IV.

### "rc4"
Output the shellcode as an array of RC4 encrypted shellcode with a given key.

### "xor"
Output the shellcode as an array of XOR encrypted shellcode with a given key.

## Arguments:

```bash
<mode>: 
```
The mode to determine the output format (as described above).

```bash
<payload_file>: 
```
The file containing the payload to be processed.

```
bash[key]: 
(Optional) The key used for encryption modes (e.g., for RC4 or XOR).
```
```bash
-o <output_file>: 
```
(Optional) Specify an output file to save the result.