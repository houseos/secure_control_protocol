/*
secure_control_protocol
Discover Command Class
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
      )
      ..addOption(
        'json',
        abbr: 'j',
        help: 'Path to the JSON file containing all known devices.',
        valueHelp: 'Path in the filesystem.',
      );
  }

  void run() async {
    print('scp_client Discover');

    // validate parameters

    if (!InputValidation.isIpAddress(argResults?['ipaddress'])) {
      print(
          'IP Address parameter invalid, only IPv4 in dotted-decimal notation allowed.');
      return;
    }

    if (!InputValidation.isSubnetMask(argResults?['mask'])) {
      print('Subnet Mask invalid.');
      return;
    }

    Scp scp = Scp.getInstance();
    scp.enableLogging();
    String filePath = argResults?['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      await scp.knownDevicesFromFile(file);
      print("known devices before discover:");
      print(scp.knownDevices);
      await scp.doDiscover(argResults?['ipaddress'], argResults?['mask']);
      print(scp.newDevices);
    } else {
      print('JSON file does not exist.');
    }
  }
}
