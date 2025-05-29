<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class BarqGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.barqpay.com'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.barqpay.com'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'apiKey' => '',
            'secretKey' => '',
            'merchantId' => '',
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/barq/callback',
            'timeout' => 30,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['apiKey', 'secretKey', 'merchantId'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Barq: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $params): string
    {
        // Placeholder: Barq signature logic (e.g., HMAC-SHA256)
        ksort($params);
        $stringToSign = http_build_query($params) . $this->config['secretKey'];
        return hash_hmac('sha256', $stringToSign, $this->config['secretKey']);
    }

    private function getRequestHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'X-API-KEY' => $this->config['apiKey'],
            // Potentially 'X-Signature' => $signature if calculated on whole body
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Barq: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Barq: Missing orderId.');
        }

        $payload = [
            'merchantId' => $this->config['merchantId'],
            'orderReference' => $sanitizedData['orderId'],
            'amount' => $sanitizedData['amount'],
            'currency' => $sanitizedData['currency'] ?? 'SAR',
            'callbackUrl' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'description' => $sanitizedData['description'] ?? 'Payment for order ' . $sanitizedData['orderId'],
            // ... other Barq specific parameters
        ];
        $payload['signature'] = $this->generateSignature($payload); // Or signature on specific fields

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payments', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('Barq: API rejected initialization (simulated).');
            }
            $mockBarqTxnId = 'BARQTXN' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/checkout?id=' . $mockBarqTxnId;
            
            $response = ['body' => [
                    'transactionId' => $mockBarqTxnId,
                    'paymentUrl' => $mockPaymentUrl,
                    'status' => 'CREATED',
                    'message' => 'Payment initiated'
                ],
                'status_code' => 201 // HTTP 201 Created is common for such APIs
            ];

            if ($response['status_code'] !== 201 || strtoupper($response['body']['status'] ?? '') !== 'CREATED') {
                throw new InitializationException('Barq: Failed to initialize payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Barq payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['transactionId'],
                'paymentUrl' => $response['body']['paymentUrl'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Barq: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data); // Data from Barq callback
        // Verify callback signature and data
        // $receivedSignature = $sanitizedData['signature']; unset($sanitizedData['signature']);
        // if($this->generateSignature($sanitizedData) !== $receivedSignature) { /* error */ }

        if (empty($sanitizedData['transactionId'])) {
            throw new ProcessingException('Barq: Missing transactionId in callback.');
        }

        $status = $sanitizedData['status'] ?? 'FAILED'; // e.g. SUCCESS, FAILED
        $isSuccess = strtoupper($status) === 'SUCCESS' || strtoupper($status) === 'COMPLETED';

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'Barq payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['transactionId'],
            'orderId' => $sanitizedData['orderReference'] ?? null,
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // Barq's transactionId
            throw new VerificationException('Barq: Missing gatewayReferenceId (transactionId) for verification.');
        }
        $transactionId = $sanitizedData['gatewayReferenceId'];

        $paramsToSign = ['transactionId' => $transactionId, 'merchantId' => $this->config['merchantId']];
        $signature = $this->generateSignature($paramsToSign);

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/payments/' . $transactionId . '?signature=' . $signature, [], $this->getRequestHeaders());
            // Mocked Response
            $mockStatus = 'SUCCESS'; $mockOrderId = 'ORDER' . strtoupper(uniqid());
            if ($transactionId === 'fail_verify_ref') {
                $mockStatus = 'FAILED';
            }
            $response = ['body' => [
                    'transactionId' => $transactionId,
                    'orderReference' => $mockOrderId,
                    'status' => $mockStatus, // e.g. SUCCESS, FAILED, PENDING
                    'amount' => $sanitizedData['original_amount_for_test'] ?? '100.00',
                    'message' => 'Verification successful'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || !in_array(strtoupper($response['body']['status'] ?? ''), ['SUCCESS', 'COMPLETED', 'PENDING'])) {
                 // Allow PENDING as a valid non-failure state from verify
                if (!in_array(strtoupper($response['body']['status'] ?? ''), ['PENDING'])) {
                    throw new VerificationException('Barq: Failed to verify payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
                }
            }

            $paymentStatus = $response['body']['status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'SUCCESS' || strtoupper($paymentStatus) === 'COMPLETED';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Barq verification result: ' . $paymentStatus,
                'transactionId' => $transactionId,
                'orderId' => $response['body']['orderReference'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Barq: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) {
            throw new RefundException('Barq: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Barq: Invalid or missing amount for refund.');
        }

        $payload = [
            'merchantId' => $this->config['merchantId'],
            'transactionId' => $sanitizedData['transactionId'],
            'amount' => $sanitizedData['amount'],
            'reason' => $sanitizedData['reason'] ?? 'User request'
        ];
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/refunds', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('Barq: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'refundId' => 'BARQREFUND' . strtoupper(uniqid()),
                    'status' => 'PROCESSED',
                    'message' => 'Refund successful'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'PROCESSED') {
                throw new RefundException('Barq: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success',
                'message' => 'Barq refund processed successfully.',
                'refundId' => $response['body']['refundId'] ?? null,
                'paymentStatus' => $response['body']['status'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Barq: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 