import 'dart:convert';
import 'dart:async';
import 'package:secure_control_protocol/scp_response_parser.dart';
import 'package:secure_control_protocol/util/ip_range.dart';
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_message_sender.dart';

import 'package:secure_control_protocol/scp_device.dart';

class Scp {
  // List of configured devices known to SCP
  List<ScpDevice> knownDevices;

  // List of newly discovered not configured devices
  List<ScpDevice> newDevices;

  Scp() {
    knownDevices = List<ScpDevice>();
  }

  void doDiscover(String subnet, String mask) async {
    List<ScpDevice> discoveredDevices = List<ScpDevice>();
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>();

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(requests).then(
      (List responses) => responses.forEach((response) {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            ScpResponseDiscover parsedResponse =
                ScpResponseParser.parseDiscoverResponse(response);
            if (parsedResponse != null) {
              discoveredDevices.add(
                ScpDevice(
                  deviceId: parsedResponse.deviceId,
                  deviceType: parsedResponse.deviceType,
                  currentPasswordNumber: parsedResponse.currentPassowrdNumber,
                  ipAddress: allIPs
                      .firstWhere((ip) => response.request.url.host == ip),
                  defaultPassword:
                      parsedResponse.currentPassowrdNumber == 0 ? true : false,
                ),
              );
              print(
                  'DeviceId: ${discoveredDevices.last.deviceId}, Type: ${discoveredDevices.last.deviceType}, IP: ${knownDevices.last.ipAddress}');
            }
          }
        }
      }),
    );
  }

  void doProvisioning() {
    // for each new device

    newDevices.forEach((device) {
      // get NVCN
      // generate new password
      // send security-pw-change
      // get NVCN
      // send security-wifi-config
      // get NVCN
      // send security-restart
      // move device from new devices to known devices
    });
  }
}
