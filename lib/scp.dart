import 'dart:convert';
import 'dart:async';
import 'package:secure_control_protocol/scp_response_parser.dart';
import 'package:secure_control_protocol/util/ip_range.dart';
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_message_sender.dart';

import 'package:secure_control_protocol/scp_device.dart';

class Scp {
  static Scp instance;

  // List of configured devices known to SCP
  List<ScpDevice> knownDevices;

  // List of newly discovered not configured devices
  List<ScpDevice> newDevices;

  static Scp getInstance() {
    if (Scp.instance == null) {
      Scp.instance = Scp();
    }
    return Scp.instance;
  }

  Scp() {
    knownDevices = List<ScpDevice>();
  }

  void doDiscover(String subnet, String mask) async {
    newDevices = List<ScpDevice>();
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
              ScpDevice dev = ScpDevice(
                  deviceId: parsedResponse.deviceId,
                  deviceType: parsedResponse.deviceType,
                  currentPasswordNumber: parsedResponse.currentPasswordNumber,
                  ipAddress: allIPs
                      .firstWhere((ip) => response.request.url.host == ip),
                  isDefaultPasswordSet:
                      parsedResponse.currentPasswordNumber == 0 ? true : false,
                  knownPassword: parsedResponse.currentPasswordNumber == 0
                      ? "01234567890123456789012345678901"
                      : "");
              newDevices.add(dev);
              print(dev.toString());
            }
          }
        }
      }),
    );
  }

  void doProvisioning(String ssid, String wifiPassword, bool jsonExport) async {
    // for each new device
    await newDevices.forEach((device) async {
      print('Provisioning device: ${device.deviceId}');
      // send security-pw-change
      final newPasswordResponse =
          await ScpMessageSender.sendNewPassword(device);
      if (newPasswordResponse == null) {
        print('failed to send new password');
        return;
      }
      if (newPasswordResponse != null &&
          newPasswordResponse.bodyBytes != null) {
        if (newPasswordResponse.statusCode == 200) {
          ScpResponseSetPassword parsedResponse =
              ScpResponseParser.parseSetPasswordResponse(newPasswordResponse);
          if (parsedResponse != null) {
            if (parsedResponse.result == "success") {
              print('Successfully set new password.');
              device.currentPasswordNumber = int.parse(parsedResponse.currentPasswordNumber);
              print(device.toString());
            }
          }
        }
      }
      // send security-wifi-config
      final wifiConfigResponse =
          ScpMessageSender.sendWifiConfig(device, ssid, wifiPassword);
      // send security-restart
      final restartResponse = ScpMessageSender.sendRestart(device);
      // move device from new devices to known devices
      if (restartResponse != null) {
        this.knownDevices.add(device);
        //print all device info
        print(device.toString());
      }
    });

    if (jsonExport) {
      //export all known devices to JSON
    }
  }
}
