<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PhonePeGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api-preprod.phonepe.com/apis/pg-sandbox'; // Example UAT URL
    private const API_BASE_URL_PRODUCTION = 'https://api.phonepe.com/apis/hermes'; // Example Production URL

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'saltKey' => '',
            'saltIndex' => 1, // Usually 1 or 2
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/phonepe/callback',
            'timeout' => 45,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'saltKey', 'saltIndex'] as $key) {
            if (!isset($config[$key]) || (is_string($config[$key]) && trim($config[$key]) === '') || (is_int($config[$key]) && $config[$key] < 1) ){
                 if($key === 'saltIndex' && is_int($config[$key]) && $config[$key] >=1 ) continue;
                throw new InvalidConfigurationException("PhonePe: {$key} is required and must be valid.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateChecksum(string $payloadString, string $endpoint): string
    {
        // PhonePe checksum: base64(SHA256(base64Payload + apiEndpoint + saltKey)) + ### + saltIndex
        $stringToHash = $payloadString . $endpoint . $this->config['saltKey'];
        $sha256 = hash('sha256', $stringToHash);
        return $sha256 . '###' . $this->config['saltIndex'];
    }

    private function getRequestHeaders(string $checksum): array
    {
        return [
            'Content-Type' => 'application/json',
            'X-VERIFY' => $checksum,
            // 'X-CALLBACK-URL' => $this->config['callbackUrl'], // Often part of payload for PhonePe Pay API
            // 'X-MERCHANT-ID' => $this->config['merchantId'] // Also often part of payload
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('PhonePe: Invalid or missing amount. Amount should be in Paisa (integer).');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('PhonePe: Missing orderId (merchantTransactionId).');
        }
        if (empty($sanitizedData['userId'])) {
            throw new InitializationException('PhonePe: Missing userId (merchantUserId).');
        }

        $merchantTransactionId = $sanitizedData['orderId'];
        $amountInPaisa = (int) ($sanitizedData['amount'] * 100); // PhonePe requires amount in paisa

        $payload = [
            'merchantId' => $this->config['merchantId'],
            'merchantTransactionId' => $merchantTransactionId,
            'merchantUserId' => $sanitizedData['userId'],
            'amount' => $amountInPaisa,
            'redirectUrl' => $sanitizedData['redirectUrl'] ?? $this->config['callbackUrl'], // For App/Web redirect post payment
            'redirectMode' => $sanitizedData['redirectMode'] ?? 'POST', // Or GET
            'callbackUrl' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'], // S2S callback
            'mobileNumber' => $sanitizedData['mobileNumber'] ?? null,
            'paymentInstrument' => [
                'type' => $sanitizedData['paymentType'] ?? 'PAY_PAGE', // PAY_PAGE, UPI_INTENT, etc.
            ],
            // Optional: 'deviceContext' => ['deviceOS' => 'ANDROID'] for SDK integrations
        ];

        $base64Payload = base64_encode(json_encode($payload));
        $requestBody = ['request' => $base64Payload];
        $jsonRequestBody = json_encode($requestBody);

        $endpoint = '/pg/v1/pay';
        $checksum = $this->generateChecksum($base64Payload, $endpoint);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . $endpoint, $jsonRequestBody, $this->getRequestHeaders($checksum));
            // Mocked Response
            if ($amountInPaisa == 99900) { 
                 throw new InitializationException('PhonePe: API rejected initialization (simulated).');
            }
            $mockPhonePeTxnId = 'PHONETXN' . strtoupper(uniqid());
            $mockPaymentUrl = ($this->config['isSandbox'] ? 'https://mercury-uat.phonepe.com/transact/pg?token=' : 'https://mercury.phonepe.com/transact/pg?token=') . 'MOCKTOKEN' . strtoupper(uniqid());
            
            $response = ['body' => [
                    'success' => true,
                    'code' => 'PAYMENT_INITIATED',
                    'message' => 'Payment initiated successfully',
                    'data' => [
                        'merchantId' => $this->config['merchantId'],
                        'merchantTransactionId' => $merchantTransactionId,
                        'instrumentResponse' => [
                            'type' => 'PAY_PAGE',
                            'redirectInfo' => [
                                'url' => $mockPaymentUrl,
                                'method' => 'GET'
                            ]
                        ]
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || !($response['body']['success'] ?? false)) {
                throw new InitializationException('PhonePe: Failed to initialize payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'PhonePe payment initialized. Redirect user.',
                'gatewayReferenceId' => $merchantTransactionId, // PhonePe uses merchantTransactionId as primary ref before their own ID is generated on success.
                'paymentUrl' => $response['body']['data']['instrumentResponse']['redirectInfo']['url'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('PhonePe: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for PhonePe means handling the S2S callback.
        // The callback data is usually in the request body (often base64 encoded JSON for `response` field)
        // and headers will contain X-VERIFY checksum.
        $sanitizedData = $data; // Assuming $data is already the decoded response from base64

        // $encodedResponse = $_POST['response']; // Example: if it comes as POST field
        // $receivedChecksum = $_SERVER['HTTP_X_VERIFY'];
        // $calculatedChecksum = $this->generateChecksum($encodedResponse, ''); // Endpoint might not be needed for callback verification or use a specific one
        // if ($receivedChecksum !== $calculatedChecksum) {
        //     throw new ProcessingException('PhonePe: Callback checksum mismatch.');
        // }
        // $decodedResponse = json_decode(base64_decode($encodedResponse), true);
        // $sanitizedData = $this->sanitize($decodedResponse);

        if (empty($sanitizedData['merchantId']) || empty($sanitizedData['merchantTransactionId'])) {
            throw new ProcessingException('PhonePe: Invalid callback data received.');
        }
        if ($sanitizedData['merchantId'] !== $this->config['merchantId']) {
            throw new ProcessingException('PhonePe: Merchant ID mismatch in callback.');
        }

        $code = $sanitizedData['code'] ?? 'PAYMENT_ERROR';
        $isSuccess = $code === 'PAYMENT_SUCCESS';

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'PhonePe payment processed. Code: ' . $code . ' - ' . ($sanitizedData['message'] ?? ''),
            'transactionId' => $sanitizedData['data']['transactionId'] ?? null, // PhonePe's transaction ID
            'orderId' => $sanitizedData['merchantTransactionId'],
            'amount' => isset($sanitizedData['data']['amount']) ? ($sanitizedData['data']['amount'] / 100) : null, // Amount is in paisa
            'paymentStatus' => $code,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // merchantTransactionId
            throw new VerificationException('PhonePe: Missing orderId (merchantTransactionId) for verification.');
        }

        $merchantTransactionId = $sanitizedData['orderId'];
        $endpoint = '/pg/v1/status/' . $this->config['merchantId'] . '/' . $merchantTransactionId;
        $checksum = $this->generateChecksum('', $endpoint); // Checksum for GET request often doesn't use payload string

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . $endpoint, [], $this->getRequestHeaders($checksum));
            // Mocked Response
            $mockCode = 'PAYMENT_SUCCESS';
            $mockTxnId = 'PHNPETXN' . strtoupper(uniqid());
            if ($merchantTransactionId === 'fail_verify') {
                $mockCode = 'PAYMENT_ERROR'; $mockTxnId = null;
            }  else if ($merchantTransactionId === 'pending_verify') {
                $mockCode = 'PAYMENT_PENDING';
            }
            
            $response = ['body' => [
                    'success' => $mockCode === 'PAYMENT_SUCCESS' || $mockCode === 'PAYMENT_PENDING',
                    'code' => $mockCode,
                    'message' => 'Status check successful',
                    'data' => [
                        'merchantId' => $this->config['merchantId'],
                        'merchantTransactionId' => $merchantTransactionId,
                        'transactionId' => $mockTxnId,
                        'amount' => ($sanitizedData['original_amount_for_test'] ?? 100) * 100, // paisa
                        'state' => ($mockCode === 'PAYMENT_SUCCESS' ? 'COMPLETED' : ($mockCode === 'PAYMENT_PENDING' ? 'PENDING' : 'FAILED')),
                        'responseCode' => $mockCode
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || !($response['body']['success'] ?? false)) {
                // If success is false but code indicates pending, it might not be a hard error yet
                if (($response['body']['code'] ?? '') !== 'PAYMENT_PENDING') {
                     throw new VerificationException('PhonePe: Failed to verify payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
                }
            }

            $paymentCode = $response['body']['code'] ?? 'UNKNOWN';
            $isSuccess = $paymentCode === 'PAYMENT_SUCCESS';
            $isPending = $paymentCode === 'PAYMENT_PENDING';

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'PhonePe verification result: ' . $paymentCode,
                'transactionId' => $response['body']['data']['transactionId'] ?? null,
                'orderId' => $response['body']['data']['merchantTransactionId'] ?? null,
                'paymentStatus' => $paymentCode,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('PhonePe: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // Original merchantTransactionId
            throw new RefundException('PhonePe: Missing original orderId (merchantTransactionId) for refund.');
        }
        if (empty($sanitizedData['transactionId'])) { // PhonePe's main transaction ID
            throw new RefundException('PhonePe: Missing transactionId (PhonePe transaction ID) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('PhonePe: Invalid or missing amount for refund. Amount should be in Paisa.');
        }

        $merchantRefundId = $sanitizedData['refundId'] ?? ('REFUND_' . $sanitizedData['orderId'] . '_' . time());
        $amountInPaisa = (int) ($sanitizedData['amount'] * 100);

        $payload = [
            'merchantId' => $this->config['merchantId'],
            'merchantUserId' => $sanitizedData['userId'] ?? 'DEFAULT_USER',
            'originalTransactionId' => $sanitizedData['transactionId'], // This is PhonePe's transactionId from successful payment
            'merchantTransactionId' => $merchantRefundId, // Unique ID for this refund transaction
            'amount' => $amountInPaisa,
            'callbackUrl' => $sanitizedData['refundCallbackUrl'] ?? ($this->config['callbackUrl'] . '/refund'),
        ];
        $base64Payload = base64_encode(json_encode($payload));
        $requestBody = ['request' => $base64Payload];
        $jsonRequestBody = json_encode($requestBody);

        $endpoint = '/pg/v1/refund';
        $checksum = $this->generateChecksum($base64Payload, $endpoint);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . $endpoint, $jsonRequestBody, $this->getRequestHeaders($checksum));
            // Mocked response
            if ($amountInPaisa == 99900) { 
                 throw new RefundException('PhonePe: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'success' => true,
                    'code' => 'REFUND_INITIATED', // Or REFUND_SUCCESS, REFUND_FAILED
                    'message' => 'Refund initiated successfully',
                    'data' => [
                        'merchantId' => $this->config['merchantId'],
                        'merchantTransactionId' => $merchantRefundId,
                        'transactionId' => 'PHNPEREF' . strtoupper(uniqid()),
                        'amount' => $amountInPaisa,
                        'state' => 'PENDING' // Or COMPLETED, FAILED
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || !($response['body']['success'] ?? false)) {
                throw new RefundException('PhonePe: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $refundStatus = $response['body']['data']['state'] ?? 'UNKNOWN';
            return [
                'status' => strtolower($refundStatus) === 'completed' ? 'success' : (strtolower($refundStatus) === 'pending' ? 'pending' : 'failed'),
                'message' => 'PhonePe refund status: ' . $refundStatus,
                'refundId' => $response['body']['data']['transactionId'] ?? $merchantRefundId,
                'paymentStatus' => $refundStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('PhonePe: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 