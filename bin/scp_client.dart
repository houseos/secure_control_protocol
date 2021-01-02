/*
secure_control_protocol
SCP CLI Client
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:io';

// 3rd Party Libraries
import 'package:args/command_runner.dart';

// SCP
import 'package:secure_control_protocol/scp.dart';
import 'package:secure_control_protocol/util/input_validation.dart';

void main(List<String> args) async {
  //-d to decode and decrypt, first argument is key, second is nvcn, third is payload

  final int USAGE_ERROR = 64;

  var runner = CommandRunner(
      'dart.exe .\scp_client.dart', 'Secure Control Protocol CLI Client');

  runner
    ..addCommand(DiscoverCommand())
    ..addCommand(ProvisionCommand())
    ..addCommand(UpdateCommand())
    ..addCommand(ControlCommand())
    ..addCommand(ResetToDefaultCommand())
    ..addCommand(MeasureCommand())
    ..run(args).catchError((error) {
      if (error is! UsageException) throw error;
      print(runner.usage);
      exit(USAGE_ERROR); // Exit code 64 indicates a usage error.
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

    // validate parameters

    if (!InputValidation.isIpAddress(argResults['ipaddress'])) {
      print(
          'IP Address parameter invalid, only IPv4 in dotted-decimal notation allowed.');
      return;
    }

    if (!InputValidation.isSubnetMask(argResults['mask'])) {
      print('Subnet Mask invalid.');
      return;
    }

    Scp scp = Scp.getInstance();
    await scp.doDiscover(argResults['ipaddress'], argResults['mask']);
    print(scp.newDevices);
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

    // validate parameters

    if (!InputValidation.isIpAddress(argResults['ipaddress'])) {
      print(
          'IP Address parameter invalid, only IPv4 in dotted-decimal notation allowed.');
      return;
    }

    if (!InputValidation.isSubnetMask(argResults['mask'])) {
      print('Subnet Mask invalid.');
      return;
    }

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

class ResetToDefaultCommand extends Command {
  final name = "reset";
  final description = "Reset the selected device.";

  ResetToDefaultCommand() {
    argParser
      ..addOption(
        'deviceId',
        abbr: 'd',
        help: 'The ID of the device to control.',
        valueHelp: 'Can be looked up in the json with the provisioned devices.',
      )
      ..addOption(
        'json',
        abbr: 'j',
        help: 'Path to the JSON file containing all known devices.',
        valueHelp: 'Path in the filesystem.',
      );
  }

  void run() async {
    print('scp_client reset');
    Scp scp = Scp.getInstance();

    String filePath = argResults['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      await scp.knownDevicesFromFile(file);
      await scp.resetToDefault(
        argResults['deviceId'],
      );
    } else {
      print('JSON file does not exist.');
    }
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
        valueHelp: 'Can be looked up in the json with the provisioned devices.',
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
      await scp.knownDevicesFromFile(file);
      await scp.control(
        argResults['deviceId'],
        argResults['command'],
      );
    } else {
      print('JSON file does not exist.');
    }
  }
}

class MeasureCommand extends Command {
  final name = "measure";
  final description = "Measure a value.";

  MeasureCommand() {
    argParser
      ..addOption(
        'action',
        abbr: 'a',
        help: 'The measure action to send to the device.',
        valueHelp: 'Any string registered in the device.',
      )
      ..addOption(
        'deviceId',
        abbr: 'd',
        help: 'The ID of the device to control.',
        valueHelp: 'Can be looked up in the json with the provisioned devices.',
      )
      ..addOption(
        'json',
        abbr: 'j',
        help: 'Path to the JSON file containing all known devices.',
        valueHelp: 'Path in the filesystem.',
      );
  }
  void run() async {
    print('scp_client measure');
    Scp scp = Scp.getInstance();

    String filePath = argResults['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      await scp.knownDevicesFromFile(file);
      await scp.measure(
        argResults['deviceId'],
        argResults['action'],
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

    // validate parameters

    if (!InputValidation.isIpAddress(argResults['ipaddress'])) {
      print(
          'IP Address parameter invalid, only IPv4 in dotted-decimal notation allowed.');
      return;
    }

    if (!InputValidation.isSubnetMask(argResults['mask'])) {
      print('Subnet Mask invalid.');
      return;
    }

    String filePath = argResults['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      await scp.knownDevicesFromFile(file);
      scp.doUpdate(argResults['ipaddress'], argResults['mask'], filePath);
    } else {
      print('JSON file does not exist.');
    }
  }
}
