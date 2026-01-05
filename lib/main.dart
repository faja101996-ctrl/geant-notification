import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:googleapis_auth/auth_io.dart';

Future<dynamic> main(final context) async {
  try {
    context.log('Notification function started');
    
    final projectId = Platform.environment['FIREBASE_PROJECT_ID'] ?? '';
    final serviceAccountJson = Platform.environment['FIREBASE_SERVICE_ACCOUNT'] ?? '';
    
    if (projectId.isEmpty || serviceAccountJson.isEmpty) {
      return context.res.json({'success': false, 'error': 'Missing env vars'});
    }
    
    final serviceAccount = jsonDecode(serviceAccountJson);
    final credentials = ServiceAccountCredentials.fromJson(serviceAccount);
    final scopes = ['https://www.googleapis.com/auth/firebase.messaging'];
    final authClient = await clientViaServiceAccount(credentials, scopes);
    final accessToken = authClient.credentials.accessToken.data;
    
    context.log('Got access token');
    
    final headers = context.req.headers;
    final body = context.req.body;
    
    Map<String, dynamic> payload = {};
    if (body is String && body.isNotEmpty) {
      try { payload = jsonDecode(body); } catch (_) {}
    } else if (body is Map) {
      payload = Map<String, dynamic>.from(body);
    }
    
    final appwriteEvent = headers['x-appwrite-event']?.toString() ?? '';
    
    if (appwriteEvent.contains('products') && appwriteEvent.contains('create')) {
      return await _sendNotification(context, projectId, accessToken, 'new_products',
        'New Product!', 'New product: ${payload['name'] ?? 'Product'}',
        {'type': 'new_product', 'id': payload['\$id']?.toString() ?? ''});
    }
    
    if (appwriteEvent.contains('orders') && appwriteEvent.contains('create')) {
      return await _sendNotification(context, projectId, accessToken, 'admin_orders',
        'New Order!', 'Order from ${payload['customerName'] ?? 'Customer'} - ${payload['totalAmount'] ?? 0} DA',
        {'type': 'new_order', 'id': payload['\$id']?.toString() ?? ''});
    }
    
    final type = payload['type']?.toString() ?? '';
    if (type == 'test') {
      return await _sendNotification(context, projectId, accessToken, 'admin_orders',
        'Test', 'Test notification', {'type': 'test'});
    }
    
    return context.res.json({'success': true, 'message': 'Event: $appwriteEvent'});
  } catch (e, s) {
    context.error('Error: $e\n$s');
    return context.res.json({'success': false, 'error': e.toString()});
  }
}

Future<dynamic> _sendNotification(dynamic context, String projectId, String token, 
    String topic, String title, String body, Map<String, String> data) async {
  final response = await http.post(
    Uri.parse('https://fcm.googleapis.com/v1/projects/$projectId/messages:send'),
    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer $token'},
    body: jsonEncode({
      'message': {
        'topic': topic,
        'notification': {'title': title, 'body': body},
        'data': data,
        'android': {'priority': 'high', 'notification': {'sound': 'default', 'channel_id': 'high_importance_channel'}},
      }
    }),
  );
  context.log('FCM: ${response.statusCode} - ${response.body}');
  return context.res.json({'success': response.statusCode == 200, 'response': response.body});
}
