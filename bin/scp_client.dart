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
import 'commands/discover_command.dart';
import 'commands/provision_command.dart';
import 'commands/rename_command.dart';
import 'commands/update_command.dart';
import 'commands/control_command.dart';
import 'commands/reset_to_default_command.dart';
import 'commands/measure_command.dart';
import 'error.dart';

void main(List<String> args) async {
  //-d to decode and decrypt, first argument is key, second is nvcn, third is payload

  var runner;
  if (Platform.isWindows) {
    runner =
        CommandRunner('scp-client.exe', 'Secure Control Protocol CLI Client');
  } else {
    runner = CommandRunner('scp-client', 'Secure Control Protocol CLI Client');
  }

  runner
    ..addCommand(DiscoverCommand())
    ..addCommand(ProvisionCommand())
    ..addCommand(UpdateCommand())
    ..addCommand(ControlCommand())
    ..addCommand(ResetToDefaultCommand())
    ..addCommand(MeasureCommand())
    ..addCommand(RenameCommand())
    ..run(args).catchError((error) {
      if (error is! UsageException) throw error;
      print(runner.usage);
      exit(ScpError.USAGE_ERROR); // Exit code 64 indicates a usage error.
    });
}
