import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:secure_control_protocol/scp_crypto.dart';

void main(List<String> args) async {
  //-d to decode and decrypt, first argument is key, second is nvcn, third is payload

  var runner = CommandRunner('Test ChaCha20 Poly1305',
      'Client to test the ChaCha20 Poly 1305 Algorith with the ESP8266.');

  runner
    ..addCommand(DecryptCommand())
    ..addCommand(EncryptCommand())
    ..addCommand(SendCommand())
    ..run(args).catchError((error) {
      if (error is! UsageException) throw error;
      print(runner.usage);
      exit(64); // Exit code 64 indicates a usage error.
    });
}

class DecryptCommand extends Command {
  final name = "decrypt";
  final description = "Decrypt the given parameters.";

  DecryptCommand() {
    argParser
      ..addOption(
        'key',
        abbr: 'k',
        help: 'Encryption Key for the message',
        valueHelp: 'String (32 Characters)',
      )
      ..addOption(
        'nonce',
        abbr: 'n',
        help: 'Nonce for the encryption',
        valueHelp: 'String (12 Characters)',
      )
      ..addOption(
        'payload',
        abbr: 'p',
        help: 'The message to send.',
        valueHelp: 'String',
      );
  }

  void run() async {
    print(
        'Decrypt called with following parameters, key: ${argResults['key']}, nonce: ${argResults['nonce']}, payload: ${argResults['payload']}');
    print(await ScpCrypto().decodeThenDecrypt(
        argResults['key'], argResults['nonce'], argResults['payload']));
  }
}

class EncryptCommand extends Command {
  final name = "encrypt";
  final description = "Encrypt the given parameters.";

  EncryptCommand() {
    argParser
      ..addOption(
        'key',
        abbr: 'k',
        help: 'Encryption Key for the message',
        valueHelp: 'String (32 Characters)',
      )
      ..addOption(
        'nonce',
        abbr: 'n',
        help: 'Nonce for the encryption',
        valueHelp: 'String (12 Characters)',
      )
      ..addOption(
        'payload',
        abbr: 'p',
        help: 'The message to send.',
        valueHelp: 'String',
      );
  }

  void run() async {
    print(
        'Encrypt called with following parameters, key: ${argResults['key']}, nonce: ${argResults['nonce']}, payload: ${argResults['payload']}');

    ScpJson scpJson = await ScpCrypto().encryptThenEncode(
        argResults['key'], argResults['nonce'], argResults['payload']);
    print(scpJson.toJson());
  }
}

class TestCommand extends Command {
  final name = "test";
  final description =
      "Test the encryption and decryption with the given parameters.";

  TestCommand() {
    argParser
      ..addOption(
        'key',
        abbr: 'k',
        help: 'Encryption Key for the message',
        valueHelp: 'String (32 Characters)',
      )
      ..addOption(
        'nonce',
        abbr: 'n',
        help: 'Nonce for the encryption',
        valueHelp: 'String (12 Characters)',
      )
      ..addOption(
        'payload',
        abbr: 'p',
        help: 'The message to send.',
        valueHelp: 'String',
      );
  }

  void run() async {
    print(
        'First encrypt then decrypt with following parameters, key: ${argResults['key']}, nonce: ${argResults['nonce']}, payload: ${argResults['payload']}');

    ScpJson scpJson = await ScpCrypto().encryptThenEncode(
        argResults['key'], argResults['nonce'], argResults['payload']);
    print(await ScpCrypto().decodeThenDecrypt(
        scpJson.key, scpJson.nvcn, scpJson.encryptedPayload.base64Combined));
  }
}

class SendCommand extends Command {
  final name = "send";
  final description = "Send the given message.";

  SendCommand() {
    argParser
      ..addOption(
        'destination',
        abbr: 'd',
        help: 'Destination for the message',
        valueHelp: 'IPv4 Address (AAA.BBB.CCC.DDD)',
      )
      ..addOption(
        'key',
        abbr: 'k',
        help: 'Encryption Key for the message',
        valueHelp: 'String (32 Characters)',
      )
      ..addOption(
        'nonce',
        abbr: 'n',
        help: 'Nonce for the encryption',
        valueHelp: 'String (12 Characters)',
      )
      ..addOption(
        'payload',
        abbr: 'p',
        help: 'The message to send.',
        valueHelp: 'String',
      );
  }

  void run() async {
    ScpJson scpJson = await ScpCrypto().encryptThenEncode(
        argResults['key'], argResults['nonce'], argResults['payload']);

    String requestString =
        "http://${argResults['destination']}/decodeBase64ThenDecrypt?key=${urlEncode(scpJson.key)}&nvcn=${urlEncode(scpJson.nvcn)}&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}&payloadLength=${scpJson.encryptedPayload.dataLength}&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    final response = await http
        .get(requestString)
        .timeout(const Duration(seconds: 5))
        .catchError((e) {});

    print('${response.statusCode}: ${utf8.decode(response.bodyBytes)}');
  }
}

String urlEncode(String s) {
  return Uri.encodeQueryComponent(s);
}
