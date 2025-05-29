<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class MobilyPayGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.mobilypay.com.sa'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.mobilypay.com.sa'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'apiKey' => '',
            'secretKey' => '',
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/mobilypay/callback',
            'timeout' => 45,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'apiKey', 'secretKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Mobily Pay: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $params): string
    {
        // Placeholder: Mobily Pay signature logic (e.g., HMAC-SHA256 or similar)
        ksort($params);
        $stringToSign = http_build_query($params);
        return hash_hmac('sha256', $stringToSign, $this->config['secretKey']);
    }

    private function getRequestHeaders(?string $signature = null): array
    {
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-KEY' => $this->config['apiKey'], 
        ];
        if ($signature) {
            $headers['X-Signature'] = $signature;
        }
        return $headers;
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Mobily Pay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Mobily Pay: Missing orderId.');
        }

        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'order_id' => $sanitizedData['orderId'],
            'amount' => (float)$sanitizedData['amount'],
            'currency' => $sanitizedData['currency'] ?? 'SAR',
            'callback_url' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'description' => $sanitizedData['description'] ?? 'Payment for order ' . $sanitizedData['orderId'],
            // ... other Mobily Pay specific parameters
        ];
        // $signature = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/payments/initiate', $payload, $this->getRequestHeaders($signature));
            // Mocked Response
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('Mobily Pay: API rejected initialization (simulated).');
            }
            $mockMobilyRef = 'MOBILYREF' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/checkout/' . $mockMobilyRef;
            
            $response = ['body' => [
                    'status' => 'SUCCESS',
                    'message' => 'Payment initiated',
                    'data' => [
                        'transaction_id' => $mockMobilyRef,
                        'payment_url' => $mockPaymentUrl
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new InitializationException('Mobily Pay: Failed to initialize payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Mobily Pay payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['data']['transaction_id'],
                'paymentUrl' => $response['body']['data']['payment_url'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Mobily Pay: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data); // Data from Mobily Pay callback
        // Verify callback signature (if provided)
        // $receivedSignature = $sanitizedData['signature'] ?? '';
        // unset($sanitizedData['signature']);
        // if (!$this->verifySignature($this->generateSignature($sanitizedData), $receivedSignature)) {
        //    throw new ProcessingException('Mobily Pay: Callback signature mismatch.');
        // }

        if (empty($sanitizedData['order_id']) || empty($sanitizedData['transaction_id'])) {
            throw new ProcessingException('Mobily Pay: Missing order_id or transaction_id in callback.');
        }

        $status = $sanitizedData['status'] ?? 'FAILED'; // e.g. SUCCESS, FAILED, PENDING
        $isSuccess = strtoupper($status) === 'SUCCESS' || strtoupper($status) === 'COMPLETED';

        return [
            'status' => $isSuccess ? 'success' : (strtoupper($status) === 'PENDING' ? 'pending' : 'failed'),
            'message' => 'Mobily Pay payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['transaction_id'],
            'orderId' => $sanitizedData['order_id'],
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // Mobily Pay's transaction_id
            throw new VerificationException('Mobily Pay: Missing gatewayReferenceId (transaction_id) for verification.');
        }
        $transactionId = $sanitizedData['gatewayReferenceId'];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/v1/payments/' . $transactionId, [], $this->getRequestHeaders());
            // Mocked Response
            $mockStatus = 'COMPLETED'; $mockOrderId = 'ORDER' . strtoupper(uniqid());
            if ($transactionId === 'fail_verify_ref') {
                $mockStatus = 'FAILED';
            }
            
            $response = ['body' => [
                    'status' => 'SUCCESS',
                    'message' => 'Transaction details retrieved',
                    'data' => [
                        'transaction_id' => $transactionId,
                        'order_id' => $mockOrderId,
                        'amount' => $sanitizedData['original_amount_for_test'] ?? 100.00,
                        'status' => $mockStatus // e.g. COMPLETED, PENDING, FAILED
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new VerificationException('Mobily Pay: Failed to verify payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $paymentDetails = $response['body']['data'];
            $paymentStatus = $paymentDetails['status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'COMPLETED' || strtoupper($paymentStatus) === 'SUCCESS';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Mobily Pay verification result: ' . $paymentStatus,
                'transactionId' => $paymentDetails['transaction_id'],
                'orderId' => $paymentDetails['order_id'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Mobily Pay: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Mobily Pay's transaction_id
            throw new RefundException('Mobily Pay: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Mobily Pay: Invalid or missing amount for refund.');
        }

        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'transaction_id' => $sanitizedData['transactionId'],
            'amount' => (float)$sanitizedData['amount'],
            'reason' => $sanitizedData['reason'] ?? 'Customer request',
        ];
        // $signature = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/refunds', $payload, $this->getRequestHeaders($signature));
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('Mobily Pay: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'status' => 'SUCCESS',
                    'message' => 'Refund initiated successfully',
                    'data' => [
                        'refund_id' => 'MOBILYREFUND' . strtoupper(uniqid()),
                        'status' => 'PROCESSED' // Or PENDING
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new RefundException('Mobily Pay: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $refundApiStatus = $response['body']['data']['status'] ?? 'UNKNOWN';
            return [
                'status' => strtoupper($refundApiStatus) === 'PROCESSED' ? 'success' : (strtoupper($refundApiStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Mobily Pay refund status: ' . $refundApiStatus,
                'refundId' => $response['body']['data']['refund_id'] ?? null,
                'paymentStatus' => $refundApiStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Mobily Pay: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 