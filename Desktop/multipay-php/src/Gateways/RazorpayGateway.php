<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class RazorpayGateway extends PaymentGateway
{
    private const API_BASE_URL = 'https://api.razorpay.com/v1';

    protected function getDefaultConfig(): array
    {
        return [
            'keyId' => '', // rzp_test_xxxx or rzp_live_xxxx
            'keySecret' => '',
            'isSandbox' => true, // Razorpay uses different keys for test/live, not a URL switch typically
            'receiveCurrency' => 'INR', // Currency you wish to receive payments in (if different from display)
            'webhookSecret' => '', // For verifying webhook signatures
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['keyId', 'keySecret'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Razorpay: {$key} is required.");
            }
        }
        if (strpos($config['keyId'], 'rzp_test_') !== 0 && strpos($config['keyId'], 'rzp_live_') !== 0) {
            throw new InvalidConfigurationException("Razorpay: Invalid Key ID format.");
        }
    }

    private function getApiBaseUrl(): string
    {
        // Razorpay base URL is the same for test and live, keys determine the mode.
        return self::API_BASE_URL;
    }

    /**
     * Generate Razorpay signature for webhook or payment verification.
     * This needs the Razorpay PHP SDK or a similar robust implementation.
     */
    private function verifySignature(string $payload, string $receivedSignature, string $secret): bool
    {
        // $expectedSignature = hash_hmac('sha256', $payload, $secret);
        // return hash_equals($expectedSignature, $receivedSignature);
        if ($receivedSignature === 'FAIL_SIGNATURE') return false;
        return true; // Mock as true
    }

    private function getRequestHeaders(): array
    {
        $auth = base64_encode($this->config['keyId'] . ':' . $this->config['keySecret']);
        return [
            'Content-Type' => 'application/json',
            'Authorization' => 'Basic ' . $auth,
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Razorpay: Invalid or missing amount. Amount should be in Paisa (integer).');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Razorpay: Missing currency code (e.g., INR).');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Razorpay: Missing orderId (merchant receipt ID).');
        }

        $amountInPaisa = (int) ($sanitizedData['amount'] * 100); // Razorpay expects amount in smallest currency unit

        $payload = [
            'amount' => $amountInPaisa,
            'currency' => strtoupper($sanitizedData['currency']), // e.g. INR
            'receipt' => $sanitizedData['orderId'], // Your unique order ID
            'payment_capture' => 1, // 0 for authorize, 1 for capture
            'notes' => $sanitizedData['notes'] ?? [], // Key-value pair, e.g. ['custom_field' => 'value']
            // 'partial_payment' => false, // Optional
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/orders', $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($amountInPaisa == 99900) { 
                 throw new InitializationException('Razorpay: API rejected order creation (simulated).');
            }
            $mockRazorpayOrderId = 'order_' . strtoupper(uniqid());
            
            $response = ['body' => [
                    'id' => $mockRazorpayOrderId,
                    'entity' => 'order',
                    'amount' => $amountInPaisa,
                    'amount_paid' => 0,
                    'amount_due' => $amountInPaisa,
                    'currency' => strtoupper($sanitizedData['currency']),
                    'receipt' => $sanitizedData['orderId'],
                    'status' => 'created', // created, attempted, paid
                    'attempts' => 0,
                    'notes' => $payload['notes'],
                    'created_at' => time()
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                throw new InitializationException('Razorpay: Failed to create order. API Error: ' . ($response['body']['error']['description'] ?? 'Unknown error'));
            }

            // For Razorpay standard checkout, you get an order_id. This is then passed to their JS checkout library.
            // The `paymentUrl` here is conceptual; actual integration needs their JS.
            return [
                'status' => 'created', // Razorpay order created, client-side JS handles payment form
                'message' => 'Razorpay order created. Proceed with client-side checkout.',
                'gatewayReferenceId' => $response['body']['id'], // This is Razorpay Order ID
                'keyId' => $this->config['keyId'], // Needed for JS checkout
                'orderData' => $response['body'], // Full order data for JS checkout
                'paymentUrl' => null, // No direct redirect URL, JS handles UI
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Razorpay: Order creation request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Razorpay typically means handling a webhook or verifying payment details after JS checkout.
        // $data would contain `razorpay_payment_id`, `razorpay_order_id`, `razorpay_signature` (from JS callback or webhook).
        $sanitizedData = $this->sanitize($data);

        if (empty($sanitizedData['razorpay_payment_id'])) {
            throw new ProcessingException('Razorpay: Missing razorpay_payment_id.');
        }
        if (empty($sanitizedData['razorpay_order_id'])) {
            throw new ProcessingException('Razorpay: Missing razorpay_order_id.');
        }
        if (empty($sanitizedData['razorpay_signature'])) {
            throw new ProcessingException('Razorpay: Missing razorpay_signature.');
        }
        if (empty($this->config['webhookSecret'])){
            // throw new InvalidConfigurationException('Razorpay: Webhook Secret is required for signature verification.');
            // For now, mock it, but this is crucial for production.
        }

        // Construct payload string for signature verification: order_id + "|" + payment_id
        // $payloadToVerify = $sanitizedData['razorpay_order_id'] . '|' . $sanitizedData['razorpay_payment_id'];
        // if (!$this->verifySignature($payloadToVerify, $sanitizedData['razorpay_signature'], $this->config['webhookSecret'])) {
        //     throw new ProcessingException('Razorpay: Payment signature verification failed.');
        // }

        // At this point, signature is verified. Fetch payment details for authoritative status (recommended).
        // For mock: assume successful if signature was (mock) verified.
        $paymentDetails = $this->verify(['gatewayReferenceId' => $sanitizedData['razorpay_payment_id'], 'isPaymentId' => true]);

        return [
            'status' => $paymentDetails['status'],
            'message' => $paymentDetails['message'],
            'transactionId' => $sanitizedData['razorpay_payment_id'], // This is the Payment ID
            'orderId' => $sanitizedData['razorpay_order_id'],     // This is the Order ID
            'paymentStatus' => $paymentDetails['paymentStatus'],
            'amount' => $paymentDetails['amount'] ?? null, // Amount from verify call
            'rawData' => array_merge($sanitizedData, ['verifiedDetails' => $paymentDetails['rawData']])
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        // Razorpay can verify an Order ID or a Payment ID.
        // If `isPaymentId` is true, `gatewayReferenceId` is a payment_id, else it's an order_id.
        $isPaymentIdLookup = $sanitizedData['isPaymentId'] ?? false;
        $idToVerify = $sanitizedData['gatewayReferenceId'] ?? null;

        if (empty($idToVerify)) {
            throw new VerificationException('Razorpay: Missing gatewayReferenceId (Order ID or Payment ID) for verification.');
        }

        $endpoint = $isPaymentIdLookup ? ('/payments/' . $idToVerify) : ('/orders/' . $idToVerify);

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . $endpoint, [], $this->getRequestHeaders());
            // Mocked Response
            $mockStatus = $isPaymentIdLookup ? 'captured' : 'paid'; // payment status vs order status
            if ($idToVerify === 'fail_verify_ord' || $idToVerify === 'fail_verify_pay') {
                $mockStatus = $isPaymentIdLookup ? 'failed' : 'created'; // e.g. order created but payment failed
            }
            
            $body = [
                'id' => $idToVerify,
                'entity' => $isPaymentIdLookup ? 'payment' : 'order',
                'amount' => ($sanitizedData['original_amount_for_test'] ?? 100) * 100,
                'currency' => $this->config['receiveCurrency'],
                'status' => $mockStatus,
            ];
            if ($isPaymentIdLookup) {
                $body['order_id'] = 'order_SIMULATED' . strtoupper(uniqid());
                $body['method'] = 'card';
                $body['captured'] = ($mockStatus === 'captured');
            } else {
                $body['receipt'] = 'receipt_SIMULATED' . strtoupper(uniqid());
                $body['amount_paid'] = ($mockStatus === 'paid' ? $body['amount'] : 0);
            }
            $response = ['body' => $body, 'status_code' => 200];

            if ($response['status_code'] !== 200 || empty($response['body']['status'])) {
                throw new VerificationException('Razorpay: Failed to verify. API Error: ' . ($response['body']['error']['description'] ?? 'Unknown error'));
            }

            $paymentStatus = $response['body']['status'];
            $isSuccess = ($isPaymentIdLookup && $paymentStatus === 'captured') || (!$isPaymentIdLookup && $paymentStatus === 'paid');
            $isPending = (!$isPaymentIdLookup && $paymentStatus === 'created') || (!$isPaymentIdLookup && $paymentStatus === 'attempted');

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Razorpay verification result: ' . $paymentStatus,
                'transactionId' => $isPaymentIdLookup ? $response['body']['id'] : null, // If verifying order, payment ID might not be available directly
                'orderId' => $isPaymentIdLookup ? ($response['body']['order_id'] ?? null) : $response['body']['id'],
                'amount' => ($response['body']['amount'] ?? 0) / 100,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Razorpay: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Razorpay Payment ID (pay_xxxx)
            throw new RefundException('Razorpay: Missing transactionId (Payment ID) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Razorpay: Invalid or missing amount for refund. Amount in Paisa.');
        }

        $paymentId = $sanitizedData['transactionId'];
        $amountInPaisa = (int) ($sanitizedData['amount'] * 100);

        $payload = [
            'amount' => $amountInPaisa,
            // 'speed' => 'normal', // or 'optimum'
            'notes' => $sanitizedData['notes'] ?? [],
            'receipt' => $sanitizedData['refundReceiptId'] ?? null, // Optional: your unique ID for this refund
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payments/' . $paymentId . '/refund', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($amountInPaisa == 99900) { 
                 throw new RefundException('Razorpay: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'id' => 'rfnd_' . strtoupper(uniqid()),
                    'entity' => 'refund',
                    'amount' => $amountInPaisa,
                    'currency' => $this->config['receiveCurrency'],
                    'payment_id' => $paymentId,
                    'status' => 'processed', // or pending, failed
                    'created_at' => time()
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                throw new RefundException('Razorpay: Failed to process refund. API Error: ' . ($response['body']['error']['description'] ?? 'Unknown error'));
            }
            
            $refundStatus = $response['body']['status'] ?? 'failed';
            return [
                'status' => $refundStatus === 'processed' ? 'success' : ($refundStatus === 'pending' ? 'pending' : 'failed'),
                'message' => 'Razorpay refund status: ' . $refundStatus,
                'refundId' => $response['body']['id'],
                'transactionId' => $response['body']['payment_id'] ?? null,
                'paymentStatus' => $refundStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Razorpay: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 