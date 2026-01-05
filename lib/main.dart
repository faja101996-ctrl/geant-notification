import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';

/// Appwrite Function Entry Point
/// This function sends Firebase Cloud Messaging notifications
Future<dynamic> main(final context) async {
  try {
    context.log('Notification function started');
    
    // Get environment variables
    final projectId = Platform.environment['FIREBASE_PROJECT_ID'] ?? '';
    final serviceAccountJson = Platform.environment['FIREBASE_SERVICE_ACCOUNT'] ?? '';
    
    if (projectId.isEmpty || serviceAccountJson.isEmpty) {
      context.error('Missing Firebase configuration');
      return context.res.json({
        'success': false,
        'error': 'Missing FIREBASE_PROJECT_ID or FIREBASE_SERVICE_ACCOUNT environment variables'
      });
    }
    
    // Parse service account
    Map<String, dynamic> serviceAccount;
    try {
      serviceAccount = jsonDecode(serviceAccountJson);
    } catch (e) {
      context.error('Failed to parse service account JSON: $e');
      return context.res.json({
        'success': false,
        'error': 'Invalid FIREBASE_SERVICE_ACCOUNT JSON format'
      });
    }
    
    // Get access token using service account
    final accessToken = await _getAccessToken(serviceAccount, context);
    if (accessToken == null) {
      return context.res.json({
        'success': false,
        'error': 'Failed to get Firebase access token'
      });
    }
    
    context.log('Got Firebase access token');
    
    // Check if this is an event trigger or HTTP request
    final headers = context.req.headers;
    final body = context.req.body;
    
    // Parse the body
    Map<String, dynamic> payload;
    if (body is String && body.isNotEmpty) {
      try {
        payload = jsonDecode(body);
      } catch (e) {
        payload = {};
      }
    } else if (body is Map) {
      payload = Map<String, dynamic>.from(body);
    } else {
      payload = {};
    }
    
    // Check for Appwrite event
    final appwriteEvent = headers['x-appwrite-event']?.toString() ?? '';
    
    if (appwriteEvent.isNotEmpty) {
      context.log('Appwrite Event: $appwriteEvent');
      return await _handleAppwriteEvent(context, appwriteEvent, payload, projectId, accessToken);
    }
    
    // Handle direct HTTP request
    final type = payload['type'] as String? ?? '';
    context.log('Notification type: $type');
    
    switch (type) {
      case 'new_product':
        return await _sendTopicNotification(
          context: context,
          projectId: projectId,
          accessToken: accessToken,
          topic: 'new_products',
          title: 'New Product!',
          body: 'New product added: ${payload['productName'] ?? 'Product'}',
          data: {
            'type': 'new_product',
            'id': payload['productId']?.toString() ?? '',
          },
        );
        
      case 'new_order':
        return await _sendTopicNotification(
          context: context,
          projectId: projectId,
          accessToken: accessToken,
          topic: 'admin_orders',
          title: 'New Order!',
          body: 'New order from ${payload['customerName'] ?? 'Customer'} - ${payload['totalAmount'] ?? 0} DA',
          data: {
            'type': 'new_order',
            'id': payload['orderId']?.toString() ?? '',
          },
        );
        
      case 'test':
        return await _sendTopicNotification(
          context: context,
          projectId: projectId,
          accessToken: accessToken,
          topic: 'admin_orders',
          title: 'Test Notification',
          body: 'This is a test notification',
          data: {
            'type': 'test',
            'timestamp': DateTime.now().toIso8601String(),
          },
        );
        
      default:
        return context.res.json({
          'success': false,
          'error': 'Unknown notification type: $type'
        });
    }
    
  } catch (e, stack) {
    context.error('Error: $e');
    context.error('Stack: $stack');
    return context.res.json({
      'success': false,
      'error': e.toString()
    });
  }
}

/// Handle Appwrite database events
Future<dynamic> _handleAppwriteEvent(
  dynamic context,
  String event,
  Map<String, dynamic> payload,
  String projectId,
  String accessToken,
) async {
  context.log('Handling Appwrite event: $event');
  
  // New product created
  if (event.contains('products') && event.contains('create')) {
    context.log('New product event detected');
    return await _sendTopicNotification(
      context: context,
      projectId: projectId,
      accessToken: accessToken,
      topic: 'new_products',
      title: 'New Product!',
      body: 'New product added: ${payload['name'] ?? 'New product'}',
      data: {
        'type': 'new_product',
        'id': payload['\$id']?.toString() ?? '',
      },
    );
  }
  
  // New order created
  if (event.contains('orders') && event.contains('create')) {
    context.log('New order event detected');
    return await _sendTopicNotification(
      context: context,
      projectId: projectId,
      accessToken: accessToken,
      topic: 'admin_orders',
      title: 'New Order!',
      body: 'New order from ${payload['customerName'] ?? 'Customer'} - ${payload['totalAmount'] ?? 0} DA',
      data: {
        'type': 'new_order',
        'id': payload['\$id']?.toString() ?? '',
      },
    );
  }
  
  return context.res.json({
    'success': true,
    'message': 'Event handled: $event'
  });
}

/// Get Firebase access token using service account
Future<String?> _getAccessToken(Map<String, dynamic> serviceAccount, dynamic context) async {
  try {
    final clientEmail = serviceAccount['client_email'] as String?;
    final privateKeyPem = serviceAccount['private_key'] as String?;
    final tokenUri = serviceAccount['token_uri'] as String? ?? 'https://oauth2.googleapis.com/token';
    
    if (clientEmail == null || privateKeyPem == null) {
      context.error('Missing client_email or private_key in service account');
      return null;
    }
    
    context.log('Creating JWT for: $clientEmail');
    
    // Create and sign JWT
    final jwt = _createSignedJwt(clientEmail, privateKeyPem, tokenUri);
    
    context.log('JWT created, requesting access token...');
    
    // Exchange JWT for access token
    final response = await http.post(
      Uri.parse('https://oauth2.googleapis.com/token'),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': jwt,
      },
    );
    
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      context.log('Access token obtained successfully');
      return data['access_token'] as String?;
    } else {
      context.error('Token error (${response.statusCode}): ${response.body}');
      return null;
    }
  } catch (e, stack) {
    context.error('Error getting access token: $e');
    context.error('Stack: $stack');
    return null;
  }
}

/// Create a properly signed JWT for Google OAuth
String _createSignedJwt(String clientEmail, String privateKeyPem, String tokenUri) {
  final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  final exp = now + 3600; // 1 hour expiry
  
  // JWT Header
  final header = {
    'alg': 'RS256',
    'typ': 'JWT'
  };
  
  // JWT Payload
  final payload = {
    'iss': clientEmail,
    'scope': 'https://www.googleapis.com/auth/firebase.messaging',
    'aud': tokenUri,
    'iat': now,
    'exp': exp
  };
  
  // Base64URL encode header and payload
  final headerB64 = _base64UrlEncode(utf8.encode(jsonEncode(header)));
  final payloadB64 = _base64UrlEncode(utf8.encode(jsonEncode(payload)));
  
  // Create signature input
  final signatureInput = '$headerB64.$payloadB64';
  
  // Sign with RSA-SHA256
  final signature = _signRsa256(signatureInput, privateKeyPem);
  
  return '$signatureInput.$signature';
}

/// Base64URL encode without padding
String _base64UrlEncode(List<int> bytes) {
  return base64Url.encode(bytes).replaceAll('=', '');
}

/// Sign data with RSA-SHA256 using PointyCastle
String _signRsa256(String data, String privateKeyPem) {
  // Parse PEM private key
  final privateKey = _parsePrivateKeyFromPem(privateKeyPem);
  
  // Create signer
  final signer = RSASigner(SHA256Digest(), '0609608648016503040201');
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
  
  // Sign
  final signature = signer.generateSignature(Uint8List.fromList(utf8.encode(data)));
  
  // Return base64url encoded signature
  return _base64UrlEncode(signature.bytes);
}

/// Parse RSA private key from PEM format
RSAPrivateKey _parsePrivateKeyFromPem(String pem) {
  // Remove PEM headers and whitespace
  final lines = pem
      .replaceAll('-----BEGIN PRIVATE KEY-----', '')
      .replaceAll('-----END PRIVATE KEY-----', '')
      .replaceAll('-----BEGIN RSA PRIVATE KEY-----', '')
      .replaceAll('-----END RSA PRIVATE KEY-----', '')
      .replaceAll('\n', '')
      .replaceAll('\r', '')
      .replaceAll(' ', '');
  
  // Decode base64
  final bytes = base64.decode(lines);
  
  // Parse ASN.1 structure
  final asn1Parser = ASN1Parser(Uint8List.fromList(bytes));
  final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
  
  // Check if it is PKCS#8 or PKCS#1 format
  if (topLevelSeq.elements!.length == 3) {
    // PKCS#8 format
    final privateKeyOctet = topLevelSeq.elements![2] as ASN1OctetString;
    final privateKeyParser = ASN1Parser(privateKeyOctet.valueBytes!);
    final privateKeySeq = privateKeyParser.nextObject() as ASN1Sequence;
    return _extractRsaPrivateKey(privateKeySeq);
  } else {
    // PKCS#1 format
    return _extractRsaPrivateKey(topLevelSeq);
  }
}

/// Extract RSA private key from ASN.1 sequence
RSAPrivateKey _extractRsaPrivateKey(ASN1Sequence seq) {
  final modulus = (seq.elements![1] as ASN1Integer).integer!;
  final privateExponent = (seq.elements![3] as ASN1Integer).integer!;
  final p = (seq.elements![4] as ASN1Integer).integer!;
  final q = (seq.elements![5] as ASN1Integer).integer!;
  
  return RSAPrivateKey(modulus, privateExponent, p, q);
}

/// Send notification to a topic
Future<dynamic> _sendTopicNotification({
  required dynamic context,
  required String projectId,
  required String accessToken,
  required String topic,
  required String title,
  required String body,
  Map<String, String>? data,
}) async {
  context.log('Sending notification to topic: $topic');
  
  final message = {
    'message': {
      'topic': topic,
      'notification': {
        'title': title,
        'body': body,
      },
      'data': data ?? {},
      'android': {
        'priority': 'high',
        'notification': {
          'sound': 'default',
          'channel_id': 'high_importance_channel',
          'default_sound': true,
          'default_vibrate_timings': true,
        },
      },
    },
  };
  
  final response = await http.post(
    Uri.parse('https://fcm.googleapis.com/v1/projects/$projectId/messages:send'),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer $accessToken',
    },
    body: jsonEncode(message),
  );
  
  context.log('FCM Response: ${response.statusCode} - ${response.body}');
  
  if (response.statusCode == 200) {
    return context.res.json({
      'success': true,
      'message': 'Notification sent to topic: $topic'
    });
  } else {
    return context.res.json({
      'success': false,
      'error': 'FCM error: ${response.body}'
    });
  }
}
