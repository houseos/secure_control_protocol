import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:secure_control_protocol/scp.dart';

void main(List<String> args) async {
  //-d to decode and decrypt, first argument is key, second is nvcn, third is payload

  var runner = CommandRunner('dart.exe .\secure_control_protocol.dart',
      'Secure Control Protocol CLI Client');

  runner
    ..addCommand(DiscoverCommand())
    ..run(args).catchError((error) {
      if (error is! UsageException) throw error;
      print(runner.usage);
      exit(64); // Exit code 64 indicates a usage error.
    });
}

class DiscoverCommand extends Command {
  final name = "discover";
  final description = "Discover all devices in a given IP range.";

  DiscoverCommand() {
    argParser
      ..addOption(
        'subnet',
        abbr: 's',
        help: 'The Subnet to be scanned.',
        valueHelp: 'IPv4 Address (AAA.BBB.CCC.DDD)',
      )
      ..addOption(
        'mask',
        abbr: 'm',
        help: 'The subnet mask of the network to scan.',
        valueHelp: '0 - 32',
      );
  }

  void run() async {
    Scp scp = Scp();
    await scp.doDiscover(argResults['subnet'], argResults['mask']);
  }
}

String urlEncode(String s) {
  return Uri.encodeQueryComponent(s);
}
