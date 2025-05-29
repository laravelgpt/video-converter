<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PaystackGateway extends PaymentGateway
{
    private const API_BASE_URL = 'https://api.paystack.co';

    protected function getDefaultConfig(): array
    {
        return [
            'secretKey' => '',       // Your Paystack Secret Key (sk_live_... or sk_test_...)
            'publicKey' => '',       // Your Paystack Public Key (pk_live_... or pk_test_...) - for client-side
            // isSandbox is implicitly handled by using test keys (sk_test_...)
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['secretKey'])) {
            throw new InvalidConfigurationException('Paystack: secretKey is required.');
        }
        // PublicKey is good to have but not strictly required for all server-to-server flows this mock might represent.
    }

    private function getApiBaseUrl(): string
    {
        return self::API_BASE_URL;
    }

    private function getRequestHeaders(): array
    {
        return [
            'Authorization' => 'Bearer ' . $this->config['secretKey'],
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-cache', // Recommended by Paystack docs
        ];
    }

    // Paystack webhooks use X-Paystack-Signature (HMAC SHA512 of payload with secret key)
    protected function verifyWebhookSignature(string $payload, string $signature): bool
    {
        // $calculatedSignature = hash_hmac('sha512', $payload, $this->config['secretKey']);
        // return hash_equals($calculatedSignature, $signature);
        if ($signature === 'FAIL_PAYSTACK_SIGNATURE') return false;
        // For testing, assume valid if not explicitly failing and if signature is present
        if (!empty($payload) && !empty($signature)) return true;
        return false;
    }

    public function initialize(array $data): array
    {
        // Initialize a transaction. Returns an authorization URL and access code.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Paystack: Invalid or missing amount. Amount should be in Kobo (NGN) or lowest currency unit.');
        }
        if (empty($sanitizedData['email'])) {
            throw new InitializationException('Paystack: Missing customer email.');
        }
        if (empty($sanitizedData['orderId'])) { // reference
            throw new InitializationException('Paystack: Missing orderId (reference).');
        }

        $payload = [
            'email' => $sanitizedData['email'],
            'amount' => (int)round($sanitizedData['amount']), // Amount in Kobo (integer)
            'currency' => strtoupper($sanitizedData['currency'] ?? 'NGN'), // Default to NGN if not specified
            'reference' => $sanitizedData['orderId'],
            'callback_url' => $sanitizedData['returnUrl'] ?? 'https://example.com/paystack/return',
            'metadata' => [
                'order_id' => $sanitizedData['orderId'],
                'description' => $sanitizedData['description'] ?? ('Payment for ' . $sanitizedData['orderId']),
                // 'custom_fields' => [ ... ] // Array of custom fields if needed
            ],
            // 'channels' => ['card', 'bank', 'ussd', 'qr', 'mobile_money'] // Optional: specify payment channels
        ];

        try {
            // $url = $this->getApiBaseUrl() . '/transaction/initialize';
            // $response = $this->httpClient('POST', $url, $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($payload['amount'] == 999999) { // 9999.99 NGN
                 throw new InitializationException('Paystack: API rejected transaction initialization (simulated amount error).');
            }
            $mockAccessCode = 'ACCESSCODE_' . strtoupper(uniqid());
            $mockAuthUrl = 'https://checkout.paystack.com/' . $mockAccessCode;
            $mockResponseBody = [
                'status' => true,
                'message' => 'Authorization URL created',
                'data' => [
                    'authorization_url' => $mockAuthUrl,
                    'access_code' => $mockAccessCode,
                    'reference' => $payload['reference']
                ]
            ];
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || !($response['body']['status'] ?? false) || empty($response['body']['data']['authorization_url'])) {
                throw new InitializationException('Paystack: Failed to initialize transaction. Error: ' . ($response['body']['message'] ?? 'Unknown API error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Paystack transaction initialized. Redirect user to authorization URL.',
                'paymentUrl' => $response['body']['data']['authorization_url'],
                'accessCode' => $response['body']['data']['access_code'],
                'orderId' => $response['body']['data']['reference'], // This is your initial reference
                'gatewayReferenceId' => $response['body']['data']['reference'], // Paystack uses your reference until transaction is complete
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Paystack: Transaction initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This processes the webhook callback from Paystack.
        $sanitizedData = $this->sanitize($data); // This is the webhook payload.

        // Verify webhook signature (CRITICAL!)
        // $rawPayload = file_get_contents('php://input'); // Use raw payload for signature verification
        // $receivedSignature = $_SERVER['HTTP_X_PAYSTACK_SIGNATURE'] ?? '';
        // if (!$this->verifyWebhookSignature($rawPayload, $receivedSignature)) {
        //     throw new ProcessingException('Paystack Webhook: Signature verification failed.');
        // }

        if (empty($sanitizedData['event']) || empty($sanitizedData['data']['reference'])) {
            throw new ProcessingException('Paystack Webhook: Invalid payload. Missing event or data.reference.');
        }

        $eventData = $sanitizedData['data'];
        $eventType = $sanitizedData['event'];
        $txStatus = strtolower($eventData['status'] ?? ''); // e.g. success, failed, abandoned

        $finalStatus = 'failed';
        $message = 'Paystack webhook event: ' . $eventType . ', Status: ' . $txStatus;

        // Common success event: charge.success
        if ($eventType === 'charge.success' && $txStatus === 'success') {
            $finalStatus = 'success';
        } elseif ($eventType === 'transfer.success') { // For refund success from Paystack Transfers API
            $finalStatus = 'refunded'; // Custom status
            $message = 'Paystack refund transfer successful.';
        } elseif ($eventType === 'transfer.failed' || $eventType === 'transfer.reversed') {
            $finalStatus = 'refund_failed'; // Custom status
            $message = 'Paystack refund transfer failed or reversed.';
        } elseif ($txStatus === 'failed' || $txStatus === 'abandoned') {
            $finalStatus = 'failed';
        }
        // Handle other events: invoice.payment_failed, invoice.create, subscription.create etc.

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => (string)($eventData['id'] ?? null), // Paystack transaction ID (numeric)
            'orderId' => $eventData['reference'],         // Your reference
            'paymentStatus' => $txStatus,
            'amount' => isset($eventData['amount']) ? ($eventData['amount'] / 100) : null, // Amount is in Kobo
            'currency' => $eventData['currency'] ?? null,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Verify a transaction using Paystack's reference.
        $sanitizedData = $this->sanitize($data);
        $reference = $sanitizedData['orderId'] ?? ($sanitizedData['gatewayReferenceId'] ?? null);

        if (empty($reference)) {
            throw new VerificationException('Paystack: orderId (transaction reference) is required for verification.');
        }

        try {
            // $url = $this->getApiBaseUrl() . '/transaction/verify/' . rawurlencode($reference);
            // $response = $this->httpClient('GET', $url, [], $this->getRequestHeaders());
            // Mocked Response
            if ($reference === 'REF_FAIL_VERIFY') {
                 throw new VerificationException('Paystack: API error during verification (simulated).');
            }
            $mockResponseBody = [];
            if (strpos($reference, 'ORDER_SUCCESS') !== false || $reference === 'test_ref_success') {
                $mockResponseBody = [
                    'status' => true,
                    'message' => 'Verification successful',
                    'data' => [
                        'id' => rand(1000000, 9999999),
                        'reference' => $reference,
                        'status' => 'success',
                        'amount' => ($sanitizedData['originalAmountForTest'] ?? 5000) * 100, // Assume NGN, amount in Kobo
                        'currency' => 'NGN',
                        'gateway_response' => 'Successful',
                        'paid_at' => date('Y-m-d\TH:i:s.000\Z'),
                        'channel' => 'card',
                        'customer' => ['email' => 'test@example.com']
                        // ... other details like fees, authorization, card details etc.
                    ]
                ];
            } elseif (strpos($reference, 'ORDER_PENDING') !== false) {
                $mockResponseBody = ['status' => true, 'message' => 'Transaction pending', 'data' => ['id' => rand(100000,999999), 'reference' => $reference, 'status' => 'pending', 'amount' => 200000, 'currency' => 'NGN']];
            } else { // Simulate failed or not found
                $mockResponseBody = ['status' => false, 'message' => 'Transaction not found or failed', 'data' => null];
            }
            $response = ['body' => $mockResponseBody, 'status_code' => 200]; // Paystack usually returns 200 even for logical false status

            if (!($response['body']['status'] ?? false) || empty($response['body']['data'])) {
                // This means transaction not found or a definitive failure from Paystack's perspective.
                throw new VerificationException('Paystack: Transaction verification failed or transaction not found. Message: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $txData = $response['body']['data'];
            $currentTxStatus = strtolower($txData['status'] ?? '');
            $finalStatus = 'failed';

            if ($currentTxStatus === 'success') {
                $finalStatus = 'success';
            } elseif ($currentTxStatus === 'abandoned') {
                $finalStatus = 'failed';
            } else if (in_array($currentTxStatus, ['pending', 'ongoing', ''])) { // Empty status can sometimes mean pending
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'Paystack transaction status: ' . $currentTxStatus . ' (Gateway Msg: ' . ($response['body']['message'] ?? 'N/A') . ')',
                'transactionId' => (string)($txData['id'] ?? null), // Paystack Transaction ID
                'orderId' => $txData['reference'],
                'paymentStatus' => $currentTxStatus,
                'amount' => isset($txData['amount']) ? ($txData['amount'] / 100) : null, // Amount in Kobo
                'currency' => $txData['currency'] ?? null,
                'rawData' => $txData
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Paystack: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Paystack refunds are typically processed via the transaction reference or ID.
        // They have a specific Refund API, or refunds might be part of their Transfers API for payouts.
        // This mock will use the /refund endpoint.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId']) && empty($sanitizedData['orderId'])) { // Paystack transaction ID or your reference
            throw new RefundException('Paystack: transactionId (Paystack ID) or orderId (your reference) is required for refund.');
        }

        $payload = [
            // 'transaction' is preferred (can be ID or reference)
            'transaction' => $sanitizedData['transactionId'] ?? $sanitizedData['orderId'], 
        ];
        if (isset($sanitizedData['amount']) && is_numeric($sanitizedData['amount']) && $sanitizedData['amount'] > 0) {
            $payload['amount'] = (int)round($sanitizedData['amount']); // Amount in Kobo for refund
        }
        if (!empty($sanitizedData['reason'])) {
            $payload['customer_note'] = $sanitizedData['reason'];
        }
        // 'merchant_note' can also be added.

        try {
            // $url = $this->getApiBaseUrl() . '/refund';
            // $response = $this->httpClient('POST', $url, $payload, $this->getRequestHeaders());
            // Mocked Response
            if (($payload['amount'] ?? 0) == 9999) {
                 throw new RefundException('Paystack: API rejected refund (simulated amount error).');
            }
            $mockResponseBody = [];
            if ($payload['transaction'] === 'REF_NO_REFUND'){
                $mockResponseBody = ['status' => false, 'message' => 'Transaction has already been fully refunded', 'data' => null];
            } else {
                 $mockResponseBody = [
                    'status' => true,
                    'message' => 'Refund request successful', // Or similar message
                    'data' => [
                        'transaction' => ['id' => ($payload['transaction'] === '12345REF' ? 12345 : rand(1,10000) ), 'status' => 'reversed'], // Status of original txn might show 'reversed'
                        'dispute' => null,
                        'refund_status' => 'pending', // Or processed, failed. Paystack refunds can be async.
                        'amount' => $payload['amount'] ?? 500000, // Amount refunded in Kobo
                        'currency' => 'NGN',
                        // 'id' => rand(20000, 30000) // Sometimes a refund object ID is returned
                    ]
                ];
            }
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if (!($response['body']['status'] ?? false) || empty($response['body']['data'])) {
                throw new RefundException('Paystack: Refund API call failed. Error: ' . ($response['body']['message'] ?? 'Unknown API error'));
            }

            $refundData = $response['body']['data'];
            $finalStatus = 'pending'; // Refunds are often async
            if (strtolower($refundData['refund_status'] ?? '') === 'processed') {
                $finalStatus = 'success';
            } elseif (strtolower($refundData['refund_status'] ?? '') === 'failed') {
                $finalStatus = 'failed';
            }

            return [
                'status' => $finalStatus,
                'message' => 'Paystack refund status: ' . ($refundData['refund_status'] ?? 'N/A') . '. Gateway Msg: ' . $response['body']['message'],
                'refundId' => (string)($refundData['id'] ?? ($payload['transaction'] . '_REF')), // Paystack might not return a unique refund ID in this way, use original txn ref
                'gatewayReferenceId' => (string)($payload['transaction']), // Original transaction reference/ID
                'paymentStatus' => 'REFUND_'.strtoupper($refundData['refund_status'] ?? 'PENDING'),
                'amount' => isset($refundData['amount']) ? ($refundData['amount'] / 100) : null,
                'rawData' => $refundData
            ];
        } catch (\Exception $e) {
            throw new RefundException('Paystack: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 