<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class FlutterwaveGateway extends PaymentGateway
{
    private const API_BASE_URL_V3 = 'https://api.flutterwave.com/v3';

    protected function getDefaultConfig(): array
    {
        return [
            'secretKey' => '',       // Your Flutterwave Secret Key (SK)
            'publicKey' => '',       // Your Flutterwave Public Key (PK) - sometimes needed
            'encryptionKey' => '',   // For encrypting/decrypting request/response (if using that method)
            'isSandbox' => true,     // Flutterwave uses the same base URL, but test keys for sandbox
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        // Secret key is always required for server-side operations
        if (empty($config['secretKey'])) {
            throw new InvalidConfigurationException('Flutterwave: secretKey is required.');
        }
        // Public key might be needed for some client-side integrations or specific calls
        // Encryption key is for a specific type of secure communication, optional for many flows
    }

    private function getApiBaseUrl(): string
    {
        // Flutterwave V3 API uses the same base URL for live and test.
        // Differentiation is done via the API keys (test SK_TEST_... vs live SK_LIVE_...)
        return self::API_BASE_URL_V3;
    }

    private function getRequestHeaders(): array
    {
        return [
            'Authorization' => 'Bearer ' . $this->config['secretKey'],
            'Content-Type' => 'application/json',
        ];
    }

    // Flutterwave uses a webhook hash (X-Flutterwave-Signature or verify-hash in older versions)
    // This is typically SHA256 HMAC of the payload with your secret key.
    protected function verifyWebhookSignature(string $payload, string $signature, string $secretToken = null): bool
    {
        $localSecret = $secretToken ?? $this->config['secretKey']; // Webhook secret can be set independently
        // In newer versions, Flutterwave might use a dedicated webhook secret set in the dashboard.
        // if ($signature === hash_hmac('sha256', $payload, $localSecret)) {
        //     return true;
        // }
        if ($signature === 'FAIL_FLW_SIGNATURE') return false;
        // For testing, assume valid if not explicitly failing
        if (!empty($payload) && !empty($signature)) return true; 
        return false;
    }

    public function initialize(array $data): array
    {
        // Initializes a standard payment. Returns a link to Flutterwave's hosted payment page.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Flutterwave: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Flutterwave: Missing currency code (e.g., NGN, USD, KES).');
        }
        if (empty($sanitizedData['orderId'])) { // tx_ref
            throw new InitializationException('Flutterwave: Missing orderId (tx_ref).');
        }
        if (empty($sanitizedData['email'])) {
            throw new InitializationException('Flutterwave: Missing customer email.');
        }

        $payload = [
            'tx_ref' => $sanitizedData['orderId'],
            'amount' => $sanitizedData['amount'],
            'currency' => strtoupper($sanitizedData['currency']),
            'redirect_url' => $sanitizedData['returnUrl'] ?? 'https://example.com/flutterwave/return',
            'payment_options' => $sanitizedData['paymentOptions'] ?? 'card,ussd,banktransfer,mpesa', // Comma-separated
            'customer' => [
                'email' => $sanitizedData['email'],
                'phonenumber' => $sanitizedData['phone'] ?? null,
                'name' => $sanitizedData['customerName'] ?? 'Valued Customer',
            ],
            'customizations' => [
                'title' => $sanitizedData['customization_title'] ?? 'Payment for Goods/Services',
                'description' => $sanitizedData['description'] ?? ('Order ' . $sanitizedData['orderId']),
                'logo' => $sanitizedData['customization_logo_url'] ?? null,
            ],
            // 'meta' => ['order_id' => $sanitizedData['orderId']] // Additional metadata
        ];

        try {
            // $url = $this->getApiBaseUrl() . '/payments';
            // $response = $this->httpClient('POST', $url, $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($payload['amount'] == 9999) {
                 throw new InitializationException('Flutterwave: API rejected payment initiation (simulated amount error).');
            }
            $mockResponseBody = [
                'status' => 'success',
                'message' => 'Hosted Link',
                'data' => [
                    'link' => 'https://checkout.flutterwave.com/v3/hosted/pay/MOCK_FLW_LINK_' . uniqid()
                ]
            ];
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || strtolower($response['body']['status'] ?? '') !== 'success' || empty($response['body']['data']['link'])) {
                throw new InitializationException('Flutterwave: Failed to initialize payment. Error: ' . ($response['body']['message'] ?? 'Unknown API error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Flutterwave payment initiated. Redirect user to payment link.',
                'paymentUrl' => $response['body']['data']['link'],
                'orderId' => $sanitizedData['orderId'], // tx_ref
                'gatewayReferenceId' => null, // Flutterwave transaction ID comes after payment completion
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Flutterwave: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This processes the webhook callback from Flutterwave.
        // Flutterwave sends event notifications for transaction status changes.
        $sanitizedData = $this->sanitize($data); // This is the webhook payload.

        // Verify webhook signature (important!)
        // $receivedSignature = $_SERVER['HTTP_X_FLUTTERWAVE_SIGNATURE'] ?? ''; // Example, get from actual header
        // $rawPayload = file_get_contents('php://input'); // Use the raw payload for signature verification
        // if (!$this->verifyWebhookSignature($rawPayload, $receivedSignature, $this->config['webhookSecret'] ?? null)) {
        //     throw new ProcessingException('Flutterwave Webhook: Signature verification failed.');
        // }

        // Common event structure: { event: 'charge.completed', data: { id, tx_ref, status, amount, currency, ... } }
        if (empty($sanitizedData['event']) || empty($sanitizedData['data']['id']) || empty($sanitizedData['data']['tx_ref'])) {
            throw new ProcessingException('Flutterwave Webhook: Invalid payload. Missing event type, data.id, or data.tx_ref.');
        }

        $eventData = $sanitizedData['data'];
        $eventType = $sanitizedData['event'];
        $txStatus = strtolower($eventData['status'] ?? '');

        $finalStatus = 'failed';
        $message = 'Flutterwave webhook event: ' . $eventType . ', Status: ' . $txStatus;

        if ($eventType === 'charge.completed') {
            if ($txStatus === 'successful') {
                $finalStatus = 'success';
            } elseif (in_array($txStatus, ['pending', 'initiated'])) {
                $finalStatus = 'pending';
            } else {
                $finalStatus = 'failed';
            }
        } elseif ($eventType === 'transfer.completed' && $txStatus === 'successful'){ // Example for refund webhook
             $finalStatus = 'refunded'; // Or a custom status for refund success
             $message = 'Flutterwave refund transfer completed successfully.';
        } elseif (str_contains($eventType, '.failed') || $txStatus === 'failed'){
            $finalStatus = 'failed';
        }
        // Handle other events like charge.failed, transfer.failed etc.

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => (string)$eventData['id'], // Flutterwave transaction ID
            'orderId' => $eventData['tx_ref'],         // Your reference (tx_ref)
            'paymentStatus' => $txStatus,
            'amount' => $eventData['amount'] ?? null,
            'currency' => $eventData['currency'] ?? null,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Verify a transaction status using Flutterwave Transaction ID or your tx_ref.
        $sanitizedData = $this->sanitize($data);
        $transactionId = $sanitizedData['transactionId'] ?? null; // Flutterwave's numeric ID
        $txRef = $sanitizedData['orderId'] ?? null; // Your transaction reference

        if (empty($transactionId) && empty($txRef)) {
            throw new VerificationException('Flutterwave: Either transactionId or orderId (tx_ref) is required for verification.');
        }

        $url = null;
        if ($transactionId) {
            // Note: Flutterwave docs recommend verifying by tx_ref if possible, but direct ID verification is also an option.
            // However, the `/transactions/{id}/verify` endpoint might be what you're looking for if you have the numeric ID.
            $url = $this->getApiBaseUrl() . '/transactions/' . $transactionId . '/verify';
        } else { // Fallback or preferred method: verify by tx_ref.
            // The V2 way was `https://api.ravepay.co/flwv3-pug/getpaidx/api/v2/verify` with POST and txref + SECKEY
            // V3 recommends `/transactions/verify_by_reference?tx_ref={tx_ref}` with GET
            // Or sometimes just `/transactions?tx_ref={tx_ref}` might return an array, first element is the transaction.
            // For this mock, let's assume direct ID verification or query by tx_ref.
            // Using `/transactions/{id}/verify` is generally more direct if ID is known.
            // Let's simulate a GET to /transactions with tx_ref for cases where ID is not known.
            // Actually, the specific endpoint for verification when you have the ID is `/transactions/{ID}/verify`.
            // If you only have tx_ref, you might query `/transactions?tx_ref={TX_REF}` and get an array.
            // For simplicity, this mock will assume if transactionId is provided, it uses that direct verify endpoint.
            // If only orderId (tx_ref) is provided, we will simulate a query that might return an array.
             throw new VerificationException('Flutterwave: Using orderId (tx_ref) for verification is common. This mock will use transactionId. Provide transactionId for this mock.');
             // If we were to support tx_ref based query: (concept)
             // $url = $this->getApiBaseUrl() . '/transactions?tx_ref=' . $txRef;
        }
        

        try {
            // $response = $this->httpClient('GET', $url, [], $this->getRequestHeaders());
            // Mocked Response
            if ($transactionId === 'FLW_FAIL_VERIFY') {
                 throw new VerificationException('Flutterwave: API error during verification (simulated).');
            }
            $mockResponseBody = null;
            if ($transactionId === 'FLW12345') { // Simulate success
                $mockResponseBody = [
                    'status' => 'success',
                    'message' => 'Transaction fetched successfully',
                    'data' => [
                        'id' => (int)$transactionId,
                        'tx_ref' => $txRef ?? 'ORDER_MOCK_VERIFY_'.uniqid(),
                        'flw_ref' => 'FLWREF-'.uniqid(),
                        'status' => 'successful', // e.g. successful, failed, pending, initiated
                        'amount' => $sanitizedData['originalAmountForTest'] ?? 1000,
                        'currency' => 'NGN',
                        'payment_type' => 'card',
                        'customer' => ['email' => 'test@example.com']
                    ]
                ];
            } elseif ($transactionId === 'FLW67890') { // Simulate pending
                 $mockResponseBody = ['status' => 'success', 'message' => 'Transaction fetched', 'data' => ['id' => (int)$transactionId, 'status' => 'pending', 'tx_ref' => $txRef]];
            } else {
                 $mockResponseBody = ['status' => 'error', 'message' => 'Transaction not found', 'data' => null]; // Simulate not found
            }
            $response = ['body' => $mockResponseBody, 'status_code' => $mockResponseBody['status'] === 'error' ? 404 : 200];

            if ($response['status_code'] !== 200 || strtolower($response['body']['status'] ?? '') !== 'success' || empty($response['body']['data'])) {
                throw new VerificationException('Flutterwave: Failed to verify transaction. Error: ' . ($response['body']['message'] ?? 'Transaction not found or API error'));
            }

            $txData = $response['body']['data'];
            $currentTxStatus = strtolower($txData['status'] ?? '');
            $finalStatus = 'failed';

            if ($currentTxStatus === 'successful') {
                $finalStatus = 'success';
            } elseif (in_array($currentTxStatus, ['pending', 'initiated'])) {
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'Flutterwave transaction status: ' . $currentTxStatus . ' (Message: ' . $response['body']['message'] . ')',
                'transactionId' => (string)$txData['id'],
                'orderId' => $txData['tx_ref'],
                'paymentStatus' => $currentTxStatus,
                'amount' => $txData['amount'] ?? null,
                'currency' => $txData['currency'] ?? null,
                'rawData' => $txData
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Flutterwave: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Refunds are done via the Transaction ID (Flutterwave's numeric ID)
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Flutterwave Transaction ID
            throw new RefundException('Flutterwave: transactionId (Flutterwave numeric ID) is required for refund.');
        }
        // Amount is optional for full refund, required for partial refund.
        $amount = isset($sanitizedData['amount']) ? (float)$sanitizedData['amount'] : null;

        $payload = [];
        if ($amount !== null && $amount > 0) {
            $payload['amount'] = $amount;
        }
        // Can also add `reason` in payload: $payload['reason'] = $sanitizedData['reason'] ?? 'Merchant requested refund';

        try {
            // $url = $this->getApiBaseUrl() . '/transactions/' . $sanitizedData['transactionId'] . '/refund';
            // $response = $this->httpClient('POST', $url, $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($amount && $amount == 99.99) {
                throw new RefundException('Flutterwave: API rejected refund (simulated amount error).');
            }
            $mockResponseBody = [];
            if ($sanitizedData['transactionId'] === 'FLW_NO_REFUND'){
                $mockResponseBody = ['status' => 'error', 'message' => 'Transaction not eligible for refund', 'data' => null];
            } else {
                 $mockResponseBody = [
                    'status' => 'success',
                    'message' => 'Transaction refund initiated successfully', // Or 'Transaction refunded successfully'
                    'data' => [
                        'id' => (int)$sanitizedData['transactionId'], // Original transaction ID
                        'status' => 'pending', // Refunds might be pending initially or show original txn status
                                            // Sometimes a new transfer ID is created for the refund, check Flutterwave docs.
                        // 'flw_ref' => 'FLW_REFUND_TRANSFER_ID' // If a new ref is given
                    ]
                ];
            }
            $response = ['body' => $mockResponseBody, 'status_code' => $mockResponseBody['status'] === 'error' ? 400 : 200];


            if ($response['status_code'] !== 200 || strtolower($response['body']['status'] ?? '') !== 'success') {
                throw new RefundException('Flutterwave: Refund API call failed. Error: ' . ($response['body']['message'] ?? 'Unknown API error'));
            }

            // Refund status can be asynchronous, confirmed via webhook (e.g., transfer.completed)
            return [
                'status' => 'pending', // Or 'success' if API guarantees immediate refund
                'message' => 'Flutterwave refund request submitted. Status: ' . ($response['body']['message'] ?? 'N/A'),
                'refundId' => $sanitizedData['refundIdForGateway'] ?? ('FLWRF_'.uniqid()), // Your internal ID or one from FLW if provided
                'gatewayReferenceId' => (string)($response['body']['data']['id'] ?? $sanitizedData['transactionId']), // Original Transaction ID
                'paymentStatus' => 'REFUND_INITIATED', // Or status from response if more specific
                'rawData' => $response['body']['data'] ?? $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Flutterwave: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 