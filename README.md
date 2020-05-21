Secure Control Protocol Dart Client Library

Usage:

`-d <base64 key> <base64 nvcn> <base64 text> <base64 mac>` for decryption
`-e <key> <nvcn> <text>` for encryption
`-s <IP of target> <key> <nvcn> <text>` to send to device

Examples:

`dart .\secure_control_protocol.dart -s 192.168.2.122 01234567890123456789012345678901 012345678901 HelloWorldTest`
`dart .\secure_control_protocol.dart -s 192.168.2.122 01234567890123456789012345678901 012345678901 ThisIsAVeryLooooooooooooooooooooongTestString1234567890`
`dart .\secure_control_protocol.dart -e 01234567890123456789012345678901 012345678901 HelloWorldTest`