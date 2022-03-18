/*
secure_control_protocol
Change Name Command Class
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


class RenameCommand extends Command {
  final name = "rename";
  final description = "Rename the selected device.";

  RenameCommand() {
    argParser
      ..addOption(
        'deviceId',
        abbr: 'd',
        help: 'The ID of the device to control.',
        valueHelp: 'Can be looked up in the json with the provisioned devices.',
      )
      ..addOption(
        'name',
        abbr: 'n',
        help: 'The new name of the device.',
        valueHelp: '',
      )
      ..addOption(
        'json',
        abbr: 'j',
        help: 'Path to the JSON file containing all known devices.',
        valueHelp: 'Path in the filesystem.',
      );
  }

  void run() async {
    print('scp_client rename');

    if(!argResults!.options.contains('deviceId') || !argResults!.options.contains('name') || !argResults!.options.contains('json')){
      print(usage);
      exit(ScpError.USAGE_ERROR); // Exit code 64 indicates a usage error.
    }

    Scp scp = Scp.getInstance();
    scp.enableLogging();

    String filePath = argResults?['json'];
    if (await File('$filePath').exists()) {
      final file = await File('$filePath');
      await scp.knownDevicesFromFile(file);
      await scp.rename(
        scp.knownDevices,
        argResults?['deviceId'],
        argResults?['name'],
      );
    } else {
      print('JSON file does not exist.');
    }
  }
}
