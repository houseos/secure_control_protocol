/*
secure_control_protocol
Provision Command Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// 3rd Party Libraries
import 'package:args/command_runner.dart';

// SCP
import 'package:secure_control_protocol/scp.dart';
import 'package:secure_control_protocol/util/input_validation.dart';

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
        valueHelp: 'String (max. 32 Characters)',
      )
      ..addOption(
        'name',
        abbr: 'n',
        help: 'The new name of the device.',
        valueHelp: 'String (max. 32 Characters)',
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
    await scp.doDiscoverThenDoProvisioning(
      argResults?['ipaddress'],
      argResults?['mask'],
      argResults?['ssid'],
      argResults?['password'],
      argResults?['name'],
      argResults?['json'],
    );
  }
}
