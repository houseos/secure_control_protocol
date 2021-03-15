abstract class IValidatable {
  bool isValid();
}

class ResponseInvalidException implements Exception {
  String errMsg() => 'Response is invalid.'; 
}