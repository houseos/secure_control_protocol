/*
secure_control_protocol
Control Command Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:io';

// 3rd Party Libraries
import 'package:args/command_runner.dart';

// SCP
import 'package:secure_control_protocol/scp.dart';

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
    scp.enableLogging();

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
