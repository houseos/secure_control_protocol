/*
secure_control_protocol
Reset to Default Command Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:io';

// 3rd Party Libraries
import 'package:args/command_runner.dart';

// SCP
import 'package:secure_control_protocol/scp.dart';
import 'package:secure_control_protocol/util/error.dart';


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

    if(!argResults!.options.contains('deviceId') || !argResults!.options.contains('json')){
      print(usage);
      exit(ScpError.USAGE_ERROR); // Exit code 64 indicates a usage error.
    }

    Scp scp = Scp.getInstance();
    scp.enableLogging();

    String filePath = argResults?['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      await scp.knownDevicesFromFile(file);
      await scp.resetToDefault(
        argResults?['deviceId'],
      );
    } else {
      print('JSON file does not exist.');
    }
  }
}
