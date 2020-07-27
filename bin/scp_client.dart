import 'dart:io';
import 'dart:convert';

import 'package:args/command_runner.dart';
import 'package:secure_control_protocol/scp.dart';

void main(List<String> args) async {
  //-d to decode and decrypt, first argument is key, second is nvcn, third is payload

  var runner = CommandRunner(
      'dart.exe .\scp_client.dart', 'Secure Control Protocol CLI Client');

  runner
    ..addCommand(DiscoverCommand())
    ..addCommand(ProvisionCommand())
    ..addCommand(UpdateCommand())
    ..addCommand(ControlCommand())
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
        'ipaddress',
        abbr: 'i',
        help: 'IP address from the subnet to be scanned.',
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
    print('scp_client Discover');
    Scp scp = Scp.getInstance();
    await scp.doDiscover(argResults['ipaddress'], argResults['mask']);
  }
}

class ProvisionCommand extends Command {
  final name = "provision";
  final description = "Provision all available devices.";

  ProvisionCommand() {
    argParser
      ..addOption(
        'ipaddress',
        abbr: 'i',
        help: 'IP address from the subnet to be scanned.',
        valueHelp: 'IPv4 Address (AAA.BBB.CCC.DDD)',
      )
      ..addOption(
        'mask',
        abbr: 'm',
        help: 'The subnet mask of the network to scan.',
        valueHelp: '0 - 32',
      )
      ..addOption(
        'ssid',
        abbr: 's',
        help: 'The SSID of the Wifi the device should connect to.',
        valueHelp: 'SSID',
      )
      ..addOption(
        'password',
        abbr: 'p',
        help: 'The Wifi password.',
        valueHelp: 'String (32 Characters)',
      )
      ..addOption(
        'json',
        abbr: 'j',
        help:
            'Export the provisioned devices to the given JSON file to be able to load them for the next command.',
      );
  }

  void run() async {
    print('scp_client Provision');
    Scp scp = Scp.getInstance();
    await scp.doDiscoverThenDoProvisioning(
      argResults['ipaddress'],
      argResults['mask'],
      argResults['ssid'],
      argResults['password'],
      argResults['json'],
    );
  }
}

class ControlCommand extends Command {
  final name = "control";
  final description = "Control the selected device.";

  ControlCommand() {
    argParser
      ..addOption(
        'command',
        abbr: 'c',
        help: 'The command to send to the device.',
        valueHelp: 'Any string registered in the device.',
      )
      ..addOption(
        'deviceId',
        abbr: 'd',
        help: 'The ID of the device to control.',
        valueHelp: '0 - 32',
      )
      ..addOption(
        'json',
        abbr: 'j',
        help: 'Path to the JSON file containing all known devices.',
        valueHelp: 'Path in the filesystem.',
      );
  }

  void run() async {
    print('scp_client control');
    Scp scp = Scp.getInstance();

    String filePath = argResults['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      // Read the file
      String contents = await file.readAsString();
      var jsonString = json.decode(contents);
      scp.knownDevicesFromJson(jsonString);
      await scp.control(
        argResults['deviceId'],
        argResults['command'],
      );
    } else {
      print('JSON file does not exist.');
    }
  }
}

class UpdateCommand extends Command {
  final name = "update";
  final description =
      "Update the IP addresses of all devices in a given IP range.";

  UpdateCommand() {
    argParser
      ..addOption(
        'ipaddress',
        abbr: 'i',
        help: 'IP address from the subnet to be scanned.',
        valueHelp: 'IPv4 Address (AAA.BBB.CCC.DDD)',
      )
      ..addOption(
        'mask',
        abbr: 'm',
        help: 'The subnet mask of the network to scan.',
        valueHelp: '0 - 32',
      )
      ..addOption(
        'json',
        abbr: 'j',
        help: 'Path to the JSON file containing all known devices.',
        valueHelp: 'Path in the filesystem.',
      );
  }

  void run() async {
    print('scp_client update');
    Scp scp = Scp.getInstance();

    String filePath = argResults['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      // Read the file
      String contents = await file.readAsString();
      var jsonString = json.decode(contents);
      scp.knownDevicesFromJson(jsonString);
      scp.doUpdate(argResults['ipaddress'], argResults['mask'], filePath);
    } else {
      print('JSON file does not exist.');
    }
  }
}
