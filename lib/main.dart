import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:googleapis_auth/auth_io.dart';

/// Appwrite Function Entry Point
/// This function sends Firebase Cloud Messaging notifications
Future<dynamic> main(final context) async {
  try {
    context.log('Notification function started');

    final projectId = Platform.environment['FIREBASE_PROJECT_ID'] ?? '';
    final serviceAccountJson =
        Platform.environment['FIREBASE_SERVICE_ACCOUNT'] ?? '';

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
      try {
        payload = jsonDecode(body);
      } catch (_) {}
    } else if (body is Map) {
      payload = Map<String, dynamic>.from(body);
    }

    final appwriteEvent = headers['x-appwrite-event']?.toString() ?? '';
    context.log('Event: $appwriteEvent');

    // New product created - notify all users subscribed to new_products topic
    if (appwriteEvent.contains('products') &&
        appwriteEvent.contains('create')) {
      context.log('Sending new product notification');
      
      // Use Arabic name if available
      final productName = payload['nameAr']?.toString().isNotEmpty == true 
          ? payload['nameAr'] 
          : (payload['name'] ?? 'منتج جديد');
      final productId = payload['\$id']?.toString() ?? '';
      
      return await _sendNotification(
          context,
          projectId,
          accessToken,
          'new_products',
          '✨ منتج جديد!',
          'تم إضافة منتج جديد: $productName',
          {
            'type': 'new_product', 
            'id': productId,
            'product_id': productId,
          });
    }

    // New pack created - notify all users subscribed to new_packs topic
    if (appwriteEvent.contains('packs') && appwriteEvent.contains('create')) {
      context.log('🎁 Sending new pack notification');

      // Use Arabic title if available
      final packTitle = payload['titleAr']?.toString().isNotEmpty == true 
          ? payload['titleAr'] 
          : (payload['title'] ?? 'حزمة مميزة');
      final packId = payload['\$id']?.toString() ?? '';
      final packPrice = (payload['packPrice'] as num?)?.toDouble() ?? 0.0;
      
      // Simple notification without discount calculation (products not loaded in event)
      final notificationBody = packPrice > 0 
          ? 'عرض خاص! $packTitle - بسعر ${packPrice.toStringAsFixed(0)} دج'
          : 'عرض جديد متاح الآن! $packTitle';

      return await _sendNotification(
          context,
          projectId,
          accessToken,
          'new_packs',
          '🎁 حزمة جديدة!',
          notificationBody,
          {
            'type': 'new_pack',
            'id': packId,
            'pack_id': packId,
          });
    }

    // New order created - notify admin
    if (appwriteEvent.contains('orders') && appwriteEvent.contains('create')) {
      context.log('Sending new order notification to admin');
      final orderId = payload['\$id']?.toString() ?? '';
      final customerName = payload['customerName']?.toString() ?? 'عميل';
      final totalAmount = payload['totalAmount']?.toString() ?? '0';
      
      return await _sendNotification(
          context,
          projectId,
          accessToken,
          'admin_orders',
          '🛒 طلب جديد!',
          'طلب من $customerName - $totalAmount دج',
          {
            'type': 'new_order', 
            'id': orderId,
            'order_id': orderId,
          });
    }

    // Order updated - notify user about status change
    if (appwriteEvent.contains('orders') && appwriteEvent.contains('update')) {
      final userId = payload['userId']?.toString() ?? '';
      final status = payload['status']?.toString() ?? '';
      final orderId = payload['\$id']?.toString() ?? '';

      context.log('Order update: userId=$userId, status=$status');

      if (userId.isNotEmpty) {
        String title = 'تحديث الطلب';
        String statusText = status;

        // Translate status to Arabic
        switch (status) {
          case 'pending':
            statusText = 'قيد الانتظار';
            break;
          case 'processing':
            statusText = 'قيد التحضير';
            title = '📦 يتم تحضير طلبك!';
            break;
          case 'shipped':
            statusText = 'تم الشحن';
            title = '🚚 تم شحن طلبك!';
            break;
          case 'delivered':
            statusText = 'تم التوصيل';
            title = '✅ تم توصيل طلبك!';
            break;
          case 'cancelled':
            statusText = 'ملغي';
            title = '❌ تم إلغاء الطلب';
            break;
        }

        // Send to user-specific topic (user_{userId})
        return await _sendNotification(
            context,
            projectId,
            accessToken,
            'user_$userId',
            title,
            'حالة طلبك: $statusText',
            {
              'type': 'order_status', 
              'id': orderId,
              'order_id': orderId, 
              'status': status,
            });
      }
    }

    // Test notification
    final type = payload['type']?.toString() ?? '';
    if (type == 'test') {
      return await _sendNotification(context, projectId, accessToken,
          'admin_orders', 'Test', 'Test notification', {'type': 'test'});
    }

    return context.res
        .json({'success': true, 'message': 'Event: $appwriteEvent'});
  } catch (e, s) {
    context.error('Error: $e\n$s');
    return context.res.json({'success': false, 'error': e.toString()});
  }
}

Future<dynamic> _sendNotification(
    dynamic context,
    String projectId,
    String token,
    String topic,
    String title,
    String body,
    Map<String, String> data) async {
  context.log('Sending to topic: $topic');
  final response = await http.post(
    Uri.parse(
        'https://fcm.googleapis.com/v1/projects/$projectId/messages:send'),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer $token'
    },
    body: jsonEncode({
      'message': {
        'topic': topic,
        'notification': {'title': title, 'body': body},
        'data': data,
        'android': {
          'priority': 'high',
          'notification': {
            'sound': 'default',
            'channel_id': 'high_importance_channel'
          }
        },
      }
    }),
  );
  context.log('FCM: ${response.statusCode} - ${response.body}');
  return context.res
      .json({'success': response.statusCode == 200, 'response': response.body});
}
