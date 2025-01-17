The hash identifier project works as a universal tool to analyze a given string and identify its format or type,including various hash algorithms, Base64 encoding, ROT13 encoding, and Hexadecimal representation. Below is a detailed explanation of how the entire project functions:

Project Workflow
1. Input: User Provides a String
The tool asks the user to input a string (hash or text).
Example inputs:
5d41402abc4b2a76b9719d911017c592 (MD5)
SGVsbG8gd29ybGQ= (Base64)
Uryyb jbeyq (ROT13)
4d2 (Hexadecimal)

2. Pattern Matching for Hash Algorithms
The tool first checks the input string against regular expressions (regex) for common hash algorithms.
Each hash type has specific characteristics:
MD5: 32 characters, hexadecimal
SHA-1: 40 characters, hexadecimal
SHA-256: 64 characters, hexadecimal
bcrypt: Starts with $2, followed by a 53-character sequence
And more...


3. Special Format Detection
a. Base64 Encoding Detection
Logic:
Base64 strings have a specific structure (A-Z, a-z, 0-9, +, /, =).
Uses Python’s base64 library to verify if the string can be decoded and re-encoded successfully.
Example:
Input: SGVsbG8gd29ybGQ=
Detected as: Base64
b. ROT13 Detection
Logic:
Decodes the input using ROT13 cipher.
Checks if the result is readable text (only printable characters).
Example:
Input: Uryyb jbeyq
Detected as: ROT13
c. Hexadecimal Detection
Logic:
Matches strings that contain only hexadecimal characters (0-9, A-F).
Example:
Input: 4d2
Detected as: Hexadecimal

4. Match Compilation
The tool compiles all possible matches:
If the string matches more than one format, all formats are listed.
Example:
Input: 5d41402abc4b2a76b9719d911017c592
Output: MD5, NTLM, Hexadecimal (since MD5 and NTLM share the same length).r4
