import 'package:http/http.dart' as http;

class ScpMessageSender {
  static sendDiscoverHello(String ip) async {
    return await http
        .get('http://$ip/secure-control/discover-hello?payload=discover-hello')
        .timeout(const Duration(seconds: 1))
        .catchError((e) {});
  }
}
