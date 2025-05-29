<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class UpayGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.upay.net'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.upay.net'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'apiKey' => '',
            'secretKey' => '',
            'merchantId' => '', // Or similar identifier
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/upay/callback',
            'timeout' => 30,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['apiKey', 'secretKey', 'merchantId'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Upay: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $params): string
    {
        // Upay signature logic - placeholder
        // Usually ksort($params), http_build_query, append secret, then hash (e.g. md5 or sha256)
        ksort($params);
        $stringToSign = http_build_query($params) . $this->config['secretKey'];
        return hash('md5', $stringToSign); // Example, check Upay docs
    }

    private function getRequestHeaders(): array
    {
        // May require specific headers like API Key, or signature in header
        return [
            'Content-Type' => 'application/json',
            // 'X-API-KEY' => $this->config['apiKey'], 
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Upay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Upay: Missing orderId.');
        }

        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'order_id' => $sanitizedData['orderId'],
            'amount' => (string)$sanitizedData['amount'],
            'currency' => $sanitizedData['currency'] ?? 'BDT',
            'notify_url' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'return_url' => $sanitizedData['returnUrl'] ?? ($this->config['callbackUrl'] . '?return=true'),
            'product_name' => $sanitizedData['productName'] ?? 'Goods/Services',
            'timestamp' => time(),
            // ... other Upay specific parameters
        ];
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payment/create', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('Upay: API rejected initialization (simulated).');
            }
            $mockUpayRef = 'UPAY_REF_' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/checkout/' . $mockUpayRef; // Example structure
            
            $response = ['body' => [
                    'status' => '00', // '00' for success in some systems
                    'message' => 'Order created successfully',
                    'payment_url' => $mockPaymentUrl,
                    'gateway_reference_id' => $mockUpayRef
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['status'] ?? '') !== '00') {
                throw new InitializationException('Upay: Failed to initialize payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Upay payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['gateway_reference_id'],
                'paymentUrl' => $response['body']['payment_url'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Upay: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Upay usually means handling the callback/webhook.
        $sanitizedData = $this->sanitize($data); // Data from Upay callback

        // Verify signature from callback data (critical step)
        // $receivedSignature = $sanitizedData['signature'];
        // unset($sanitizedData['signature']); // Remove signature before generating to compare
        // if ($this->generateSignature($sanitizedData) !== $receivedSignature) {
        //     throw new ProcessingException('Upay: Callback signature mismatch.');
        // }

        if (empty($sanitizedData['order_id'])) {
            throw new ProcessingException('Upay: Missing order_id in callback.');
        }
        if (empty($sanitizedData['gateway_txn_id'])) {
             throw new ProcessingException('Upay: Missing gateway_txn_id in callback.');
        }

        $status = $sanitizedData['payment_status'] ?? 'failed'; // e.g., success, failed, pending
        $isSuccess = strtolower($status) === 'success' || strtolower($status) === 'completed';

        return [
            'status' => $isSuccess ? 'success' : (strtolower($status) === 'pending' ? 'pending' : 'failed'),
            'message' => 'Upay payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['gateway_txn_id'],
            'orderId' => $sanitizedData['order_id'],
            'amount' => $sanitizedData['amount'] ?? null,
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) {
            throw new VerificationException('Upay: Missing orderId for verification.');
        }

        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'order_id' => $sanitizedData['orderId'],
            'timestamp' => time(),
        ];
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payment/status', $payload, $this->getRequestHeaders());
            // Mocked response
            $mockStatus = 'COMPLETED'; $mockTxnId = 'UPAYTXN' . strtoupper(uniqid());
            if (($sanitizedData['orderId'] ?? '') === 'fail_verify') {
                $mockStatus = 'FAILED'; $mockTxnId = null;
            }
            
            $response = ['body' => [
                    'status' => '00',
                    'message' => 'Query successful',
                    'order_id' => $sanitizedData['orderId'],
                    'payment_status' => $mockStatus, // e.g. COMPLETED, PENDING, FAILED
                    'gateway_txn_id' => $mockTxnId,
                    'amount' => $sanitizedData['original_amount_for_test'] ?? '100.00'
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['status'] ?? '') !== '00') {
                throw new VerificationException('Upay: Failed to verify payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $paymentStatus = $response['body']['payment_status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'COMPLETED' || strtoupper($paymentStatus) === 'SUCCESS';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Upay verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['gateway_txn_id'] ?? null,
                'orderId' => $response['body']['order_id'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Upay: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Upay's gateway_txn_id
            throw new RefundException('Upay: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['orderId'])) { 
            throw new RefundException('Upay: Missing orderId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Upay: Invalid or missing amount for refund.');
        }

        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'order_id' => $sanitizedData['orderId'],
            'gateway_txn_id' => $sanitizedData['transactionId'],
            'refund_amount' => (string)$sanitizedData['amount'],
            'refund_reason' => $sanitizedData['reason'] ?? 'User request',
            'timestamp' => time(),
        ];
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payment/refund', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('Upay: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'status' => '00',
                    'message' => 'Refund successful',
                    'refund_id' => 'UPAY_REFUND_' . strtoupper(uniqid()),
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['status'] ?? '') !== '00') {
                throw new RefundException('Upay: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success',
                'message' => 'Upay refund processed successfully.',
                'refundId' => $response['body']['refund_id'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Upay: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 