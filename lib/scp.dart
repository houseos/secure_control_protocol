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
import 'package:http/http.dart';
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
  static Scp instance = Scp._();

  // List of configured devices known to SCP
  List<ScpDevice> knownDevices = List<ScpDevice>.empty(growable: true);

  // List of newly discovered not configured devices
  List<ScpDevice> newDevices = List<ScpDevice>.empty(growable: true);

  //Logging
  bool loggingEnabled = false;

  static Scp getInstance() {
    return Scp.instance;
  }

  Scp._();

  void enableLogging() {
    loggingEnabled = true;
  }

  void log(String s) {
    print('$s');
  }

  // Initialize knownDevices from JSON
  void knownDevicesFromJson(var json) {
    knownDevices = ScpDevice.devicesfromJson(json);
  }

  knownDevicesFromFile(File file) async {
    // Read the file
    String contents = await file.readAsString();
    var jsonString = json.decode(contents);
    knownDevicesFromJson(jsonString);
  }

  Future<ScpStatus> doDiscover(String subnet, String mask) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();
    List<Future<Response>> responses = List<Future<Response>>.empty(growable: true);


    Future.forEach(allIPs, (String ip) {
       responses.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    await Future.wait(responses).then(
        (List responses) => responses.forEach((response) async {
              if (response != null && response.bodyBytes != null) {
                if (response.statusCode == 200) {
                  log('Received discover response from ${response.request.url}.');
                  ScpResponseDiscover parsedResponse =
                      await ScpResponseParser.parseDiscoverResponse(
                          response, knownDevices, true);
                  if (parsedResponse.isValid()) {
                    ScpDevice dev = ScpDevice(
                      deviceId: parsedResponse.getDeviceId(),
                      deviceType: parsedResponse.getDeviceType(),
                      deviceName: parsedResponse.getDeviceName(),
                      currentPasswordNumber:
                          parsedResponse.getCurrentPasswordNumber(),
                      ipAddress: allIPs
                          .firstWhere((ip) => response.request.url.host == ip),
                      isDefaultPasswordSet:
                          parsedResponse.getCurrentPasswordNumber() == 0
                              ? true
                              : false,
                      knownPassword:
                          parsedResponse.getCurrentPasswordNumber() == 0
                              ? '01234567890123456789012345678901'
                              : '',
                      controlActions: parsedResponse.getControlActions(),
                      measureActions: parsedResponse.getMeasureActions(),
                    );
                    log('Found device: ${dev.toJson()}');
                    if (dev.isDefaultPasswordSet) {
                      log('default password set, adding to new devices.');
                      newDevices.add(dev);
                    } else {
                      log('default password not set.');
                      bool deviceKnown = false;
                      for (ScpDevice knownDevice in knownDevices) {
                        if (knownDevice.deviceId == dev.deviceId) {
                          log('Device ${dev.deviceId} already in known devices.');
                          deviceKnown = true;
                        }
                      }
                      if (deviceKnown == false) {
                        log('Device ${dev.deviceId} not in known devices, adding to known devices.');
                        knownDevices.add(dev);
                      }
                    }
                  } else {
                    log('Failed parsing response.');
                  }
                }
              }
            }), onError: (e) {
      log('Could not reach devices: $e');
    });
    return ScpStatus(status: ScpStatus.RESULT_SUCCESS);
  }

  // Updates the IP addresses of all devices in the list of known devices
  Future<ScpStatus> doUpdate(
      String subnet, String mask, String jsonPath) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future<Response>> reponses = List<Future<Response>>.empty(growable: true);

    Future.forEach(allIPs, (String ip) {
      reponses.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(reponses).then(
      (List responses) => responses.forEach((response) async {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            ScpResponseDiscover parsedResponse =
                await ScpResponseParser.parseDiscoverResponse(
                    response, knownDevices, true);
            if (parsedResponse.isValid()) {
              // Update knowDevice from discover response
              knownDevices
                  .firstWhere((element) =>
                      element.deviceId == parsedResponse.getDeviceId())
                  .updateFromDiscoverResponse(parsedResponse);
              // Update IP of knownDevices from requested IPs
              knownDevices
                      .firstWhere((element) =>
                          element.deviceId == parsedResponse.getDeviceId())
                      .ipAddress =
                  allIPs.firstWhere((ip) => response.request.url.host == ip);
              //Store this device in JsonStorage
              JsonStorage.storeDevice(
                  knownDevices.firstWhere((element) =>
                      element.deviceId == parsedResponse.getDeviceId()),
                  jsonPath);
              log('Updated device ${parsedResponse.getDeviceId()}.');
            } else {
              log('response invalid');
            }
          }
        }
      }),
    );
    return ScpStatus(status: ScpStatus.RESULT_SUCCESS);
  }

  Future<ScpStatus> doDiscoverThenDoProvisioning(String subnet, String mask,
      String ssid, String wifiPassword, String deviceName, String jsonPath) async {
    newDevices = List<ScpDevice>.empty(growable: true);
    // Get a list with all relevant IP addresses
    IPRange range = IPRange(subnet, int.parse(mask));
    List<String> allIPs = range.getAllIpAddressesInRange();

    List<Future<Response>> responses = List<Future<Response>>.empty(growable: true);

    Future.forEach(allIPs, (String ip) {
      responses.add(ScpMessageSender.sendDiscoverHello(ip));
    });

    Future.wait(responses).then(
      (List responses) => responses.forEach((response) async {
        if (response != null && response.bodyBytes != null) {
          if (response.statusCode == 200) {
            log('Received discover response.');
            ScpResponseDiscover parsedResponse =
                await ScpResponseParser.parseDiscoverResponse(
                    response, const [], false);
            if (parsedResponse.isValid()) {
              // create device
              ScpDevice dev = ScpDevice(
                  deviceId: parsedResponse.getDeviceId(),
                  deviceType: parsedResponse.getDeviceType(),
                  currentPasswordNumber:
                      parsedResponse.getCurrentPasswordNumber(),
                  ipAddress: allIPs
                      .firstWhere((ip) => response.request.url.host == ip),
                      controlActions: parsedResponse.getControlActions(),
                      measureActions: parsedResponse.getMeasureActions(),
                  isDefaultPasswordSet:
                      parsedResponse.getCurrentPasswordNumber() == 0
                          ? true
                          : false,
                  knownPassword: parsedResponse.getCurrentPasswordNumber() == 0
                      ? "01234567890123456789012345678901"
                      : "");
              log('Found device: ${dev.toString()}');

              if (dev.isDefaultPasswordSet) {
                log('default password set, adding to new devices.');
                newDevices.add(dev);
              } else {
                log('default password not set.');
                if (knownDevices
                    .contains((element) => element.deviceId == dev.deviceId)) {
                  log('Device ${dev.deviceId} already known.');
                } else {
                  log('Device ${dev.deviceId} not known, adding to known devices.');
                  List<ScpDevice> devices = List.empty(growable: true);
                  devices.addAll(knownDevices);
                  devices.add(dev);
                  knownDevices = devices;
                }
              }
              await doProvisioning(dev, ssid, wifiPassword, deviceName, jsonPath);
            } else {
              log('response invalid');
            }
          }
        }
      }),
    );

    return ScpStatus(status: ScpStatus.RESULT_SUCCESS);
  }

  Future<ScpStatus> doProvisioning(ScpDevice device, String ssid,
      String wifiPassword, String deviceName, String jsonPath) async {
    if (ssid == "" || wifiPassword == "") {
      log("provisioning without ssid or wifiPassword not possible.");
      return ScpStatus(status: ScpStatus.RESULT_ERROR);
    }

    // for each new device
    log('Provisioning device: ${device.deviceId}');
    // send security-pw-change
    await ScpMessageSender.sendNewPassword(device);

    // send security-wifi-config
    final ScpStatus wifiConfigStatus =
        await ScpMessageSender.sendWifiConfig(device, ssid, wifiPassword);
    
    if (wifiConfigStatus == ScpStatus.RESULT_ERROR) {
      log('failed to set wifi config.');
      return wifiConfigStatus;
    }
    // rename device
    final ScpStatus renameStatus = await rename([device], device.deviceId, deviceName);
    if(!(renameStatus.status == ScpStatus.RESULT_DONE)){
      return renameStatus;
    }
    // send security-restart
    final ScpStatus restartStatus =
        await ScpMessageSender.sendRestart(device);
    // move device from new devices to known devices
    if (restartStatus.status == ScpStatus.RESULT_SUCCESS) {
      log('Restarting device successfull, removing from new devices and adding to known devices.');
      List<ScpDevice> devices = List.empty(growable: true);
      devices.addAll(knownDevices);
      devices.add(device);
      knownDevices = devices;
      this
          .newDevices
          .removeWhere((element) => element.deviceId == device.deviceId);
      //print all device info
      log(device.toString());
      JsonStorage.storeDevice(device, jsonPath);
      return ScpStatus(status: ScpStatus.RESULT_SUCCESS);
    }
    return ScpStatus(status: ScpStatus.RESULT_ERROR);
  }

  Future<ScpStatus> control(String deviceId, String command) async {
    log('do control for device: $deviceId');
    final String controlResponse = await ScpMessageSender.sendControl(
        knownDevices.firstWhere((element) => element.deviceId == deviceId),
        command);
    log(controlResponse);
    if (controlResponse == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send control $command to $deviceId');
      return ScpStatus(status: ScpStatus.RESULT_SUCCESS);
    } else {
      log('Failed to send control $command to $deviceId');
      return ScpStatus(status: ScpStatus.RESULT_ERROR);
    }
  }

  Future<ScpStatusMeasure> measure(String deviceId, String action) async {
    log('do measure for device: $deviceId');
    final ScpStatusMeasure measureResponseStatus =
        await ScpMessageSender.sendMeasure(
            knownDevices.firstWhere((element) => element.deviceId == deviceId),
            action);
    if (measureResponseStatus.status == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send measure $action to $deviceId');
      return measureResponseStatus;
    } else {
      log('Failed to send measure $action to $deviceId');
      return measureResponseStatus;
    }
  }

  Future<ScpStatus> resetToDefault(String deviceId) async {
    log('reset to default for device: $deviceId');
    final ScpStatus resetToDefaultResponse =
        await ScpMessageSender.sendResetToDefault(
            knownDevices.firstWhere((element) => element.deviceId == deviceId));
    if (resetToDefaultResponse.status == ScpStatus.RESULT_SUCCESS) {
      log('Successfully send reset to default to $deviceId');
      return ScpStatus(status: ScpStatus.RESULT_SUCCESS);
    } else {
      log('Failed to send reset to default to $deviceId');
      return ScpStatus(status: ScpStatus.RESULT_ERROR);
    }
  }

  Future<ScpStatus> rename(List<ScpDevice> devices, String deviceId, String name) async {
    log('rename for device: $deviceId');
    final ScpStatus renameResponseStatus = await ScpMessageSender.sendRename(
        devices.firstWhere((element) => element.deviceId == deviceId),
        name);
    log('Rename result: $renameResponseStatus');
    if (renameResponseStatus.status == ScpStatus.RESULT_DONE) {
      log('Successfully send renamed $deviceId');
      return ScpStatus(status: ScpStatus.RESULT_DONE);
    } else {
      log('Failed to rename $deviceId');
      return ScpStatus(status: ScpStatus.RESULT_ERROR);
    }
  }
}
