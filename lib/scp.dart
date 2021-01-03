/*
secure_control_protocol
Scp Main Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:async';
import 'dart:convert';
import 'dart:io';

// SCP
import 'package:secure_control_protocol/scp_response_parser.dart';
import 'package:secure_control_protocol/scp_status.dart';
import 'package:secure_control_protocol/scp_message_sender.dart';
import 'package:secure_control_protocol/scp_device.dart';

// SCP Responses
import 'package:secure_control_protocol/scp_responses/scp_response_discover.dart';

// SCP Util
import 'package:secure_control_protocol/util/ip_range.dart';
import 'package:secure_control_protocol/util/json_storage.dart';

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
    knownDevices = List<ScpDevice>.empty(growable: true);
  }

  // Initialize knownDevices from JSON
  void knownDevicesFromJson(var json) {
    knownDevices = ScpDevice.devicesfromJson(json);
  }

  void knownDevicesFromFile(File file) async {
    // Read the file
    String contents = await file.readAsString();
    var jsonString = json.decode(contents);
    knownDevicesFromJson(jsonString);
  }

  void doDiscover(String subnet, String mask) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>.empty(growable: true);

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(requests).then(
        (List responses) => responses.forEach((response) {
              if (response != null && response.bodyBytes != null) {
                if (response.statusCode == 200) {
                  print(
                      'Received discover response from ${response.request.url}.');
                  ScpResponseDiscover parsedResponse =
                      ScpResponseParser.parseDiscoverResponseNoHmac(
                          response, null);
                  if (parsedResponse != null) {
                    ScpDevice dev = ScpDevice(
                        deviceId: parsedResponse.deviceId,
                        deviceType: parsedResponse.deviceType,
                        currentPasswordNumber:
                            parsedResponse.currentPasswordNumber,
                        ipAddress: allIPs.firstWhere(
                            (ip) => response.request.url.host == ip),
                        isDefaultPasswordSet:
                            parsedResponse.currentPasswordNumber == 0
                                ? true
                                : false,
                        knownPassword: parsedResponse.currentPasswordNumber == 0
                            ? '01234567890123456789012345678901'
                            : '');
                    if (dev.isDefaultPasswordSet) {
                      print('default password set, adding to new devices.');
                      newDevices.add(dev);
                    } else {
                      print('default password not set.');
                      if (knownDevices.contains(
                          (element) => element.deviceId == dev.deviceId)) {
                        print('Device ${dev.deviceId} already known.');
                      } else {
                        print(
                            'Device ${dev.deviceId} not known, adding to known devices.');
                        knownDevices.add(dev);
                      }
                    }
                    print('Found device: ${dev.toJson()}');
                  } else {
                    print('Failed parsing response.');
                  }
                }
              }
            }), onError: (e) {
      print('Could not reach device.');
    });
  }

  // Updates the IP addresses of all devices in the list of known devices
  void doUpdate(String subnet, String mask, String jsonPath) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>.empty(growable: true);

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(requests).then(
      (List responses) => responses.forEach((response) {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            ScpResponseDiscover parsedResponse =
                ScpResponseParser.parseDiscoverResponse(response, knownDevices);
            if (parsedResponse != null) {
              knownDevices
                      .firstWhere((element) =>
                          element.deviceId == parsedResponse.deviceId)
                      .ipAddress =
                  allIPs.firstWhere((ip) => response.request.url.host == ip);
              JsonStorage.storeDevice(
                  knownDevices.firstWhere(
                      (element) => element.deviceId == parsedResponse.deviceId),
                  jsonPath);
              print('Updated IP address of ${parsedResponse.deviceId}.');
            }
          }
        }
      }),
    );
  }

  void doDiscoverThenDoProvisioning(String subnet, String mask, String ssid,
      String wifiPassword, String jsonPath) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future> requests = List<Future>.empty(growable: true);

    await allIPs.forEach((ip) async {
      requests.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(requests).then(
      (List responses) => responses.forEach((response) async {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            print('Received discover response.');
            ScpResponseDiscover parsedResponse =
                ScpResponseParser.parseDiscoverResponse(response, null);
            if (parsedResponse != null) {
              // create device
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
              print('Found device: ${dev.toString()}');

              if (dev.isDefaultPasswordSet) {
                print('default password set, adding to new devices.');
                newDevices.add(dev);
              } else {
                print('default password not set.');
                if (knownDevices
                    .contains((element) => element.deviceId == dev.deviceId)) {
                  print('Device ${dev.deviceId} already known.');
                } else {
                  print(
                      'Device ${dev.deviceId} not known, adding to known devices.');
                  knownDevices.add(dev);
                }
              }
              await doProvisioning(dev, ssid, wifiPassword, jsonPath);
            }
          }
        }
      }),
    );
  }

  void doProvisioning(ScpDevice device, String ssid, String wifiPassword,
      String jsonPath) async {
    if (ssid == null ||
        ssid == "" ||
        wifiPassword == null ||
        wifiPassword == "") {
      print("provisioning without ssid or wifiPassword not possible.");
      return;
    }

    // for each new device
    print('Provisioning device: ${device.deviceId}');
    // send security-pw-change
    await ScpMessageSender.sendNewPassword(device);

    // send security-wifi-config
    final wifiConfigResponse =
        await ScpMessageSender.sendWifiConfig(device, ssid, wifiPassword);
    // send security-restart
    if (wifiConfigResponse == null) {
      print('wifiConfig response is null, shutting down.');
      return;
    } else if (wifiConfigResponse == ScpStatus.RESULT_ERROR) {
      print('failed to set wifi config.');
      return;
    }
    final restartResponse = await ScpMessageSender.sendRestart(device);
    // move device from new devices to known devices
    if (restartResponse != null) {
      print(
          'Restarting device successfull, removing from new devices and adding to known devices.');
      this.knownDevices.add(device);
      this
          .newDevices
          .removeWhere((element) => element.deviceId == device.deviceId);
      //print all device info
      print(device.toString());
      JsonStorage.storeDevice(device, jsonPath);
    }
  }

  void control(String deviceId, String command) async {
    print('do control for device: $deviceId');
    final controlResponse = await ScpMessageSender.sendControl(
        knownDevices.firstWhere((element) => element.deviceId == deviceId),
        command);
    print(controlResponse);
    if (controlResponse != null &&
        controlResponse == ScpStatus.RESULT_SUCCESS) {
      print('Successfully send control $command to $deviceId');
    } else {
      print('Failed to send control $command to $deviceId');
    }
  }

  void measure(String deviceId, String action) async {
    print('do measure for device: $deviceId');
    final measureResponse = await ScpMessageSender.sendMeasure(
        knownDevices.firstWhere((element) => element.deviceId == deviceId),
        action);
    print(measureResponse);
    if (measureResponse != null &&
        measureResponse == ScpStatus.RESULT_SUCCESS) {
      print('Successfully send measure $action to $deviceId');
    } else {
      print('Failed to send measure $action to $deviceId');
    }
  }

  void resetToDefault(String deviceId) async {
    print('do control for device: $deviceId');
    final resetToDefaultResponse = await ScpMessageSender.sendResetToDefault(
        knownDevices.firstWhere((element) => element.deviceId == deviceId));
    print(resetToDefaultResponse);
    if (resetToDefaultResponse != null &&
        resetToDefaultResponse == ScpStatus.RESULT_SUCCESS) {
      print('Successfully send reset to default to $deviceId');
    } else {
      print('Failed to send reset to default to $deviceId');
    }
  }
}
