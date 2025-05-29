<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class AmericanExpressGateway extends PaymentGateway
{
    // This is a generic Amex gateway. Specific product (e.g. Amex Payment Gateway) will have its own URLs.
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.americanexpress.com/payments'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.americanexpress.com/payments'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'apiKey' => '',      // Or API Username
            'apiPassword' => '', // Or API Secret / Password
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/amex/callback', // If redirect/webhook based
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'apiKey', 'apiPassword'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("American Express: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function getRequestHeaders(): array
    {
        // Auth might be Basic Auth, or custom headers with API Key.
        // $auth = base64_encode($this->config['apiKey'] . ':' . $this->config['apiPassword']);
        return [
            'Content-Type' => 'application/json',
            // 'Authorization' => 'Basic ' . $auth, // Example Basic Auth
            'X-AMEX-API-KEY' => $this->config['apiKey'], // Example custom header
            'X-AMEX-MERCHANT-ID' => $this->config['merchantId']
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('American Express: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('American Express: Missing currency code.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('American Express: Missing orderId.');
        }
        // Card details would be required here if it's a direct API post, not a redirect to Amex page.
        // For a redirect flow, fewer details are sent initially.

        $payload = [
            'merchantOrderId' => $sanitizedData['orderId'],
            'transactionAmount' => [
                'amount' => sprintf('%.2f', $sanitizedData['amount']),
                'currency' => strtoupper($sanitizedData['currency'])
            ],
            'transactionType' => 'AUTHORIZE_CAPTURE', // Or AUTHORIZE then separate CAPTURE
            'description' => $sanitizedData['description'] ?? 'Payment for ' . $sanitizedData['orderId'],
            'redirectUrl' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            // 'cardDetails' => [ 'number' => ..., 'expiryMonth' => ..., 'expiryYear' => ..., 'cvv' => ... ] // If direct post
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/charges', $payload, $this->getRequestHeaders());
            // Mocked Response (assuming a redirect flow for simplicity)
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('American Express: API rejected initialization (simulated).');
            }
            $mockAmexTxnId = 'AMEXCHG' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/checkout?session_id=' . $mockAmexTxnId; // Example structure
            
            $response = ['body' => [
                    'transactionId' => $mockAmexTxnId,
                    'status' => 'PENDING_CUSTOMER_ACTION',
                    'redirectUrl' => $mockPaymentUrl,
                    'message' => 'Redirect customer to complete payment.'
                ],
                'status_code' => 201 
            ];

            if ($response['status_code'] >= 300 || empty($response['body']['redirectUrl'])) {
                throw new InitializationException('American Express: Failed to initialize. ' . ($response['body']['errors'][0]['message'] ?? 'Unknown API error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'American Express payment initiated. Redirect user.',
                'gatewayReferenceId' => $response['body']['transactionId'],
                'paymentUrl' => $response['body']['redirectUrl'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('American Express: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Amex could be handling a webhook or data returned after redirect.
        $sanitizedData = $this->sanitize($data); 
        if (empty($sanitizedData['transactionId'])) {
            throw new ProcessingException('American Express: Missing transactionId in callback/response.');
        }
        // Verify webhook signature or authenticity of callback data if applicable.

        // For this mock, we assume `process` implies a capture if prior was an authorization.
        // Or simply re-querying the transaction via verify().
        // Let's assume the data contains final status from redirect.
        $status = $sanitizedData['status'] ?? 'FAILED'; // e.g. SUCCEEDED, FAILED, PENDING
        $isSuccess = strtoupper($status) === 'SUCCEEDED' || strtoupper($status) === 'CAPTURED';

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'American Express payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['transactionId'], // Amex Transaction ID
            'orderId' => $sanitizedData['merchantOrderId'] ?? null,
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // Amex transactionId
            throw new VerificationException('American Express: Missing gatewayReferenceId for verification.');
        }
        $transactionId = $sanitizedData['gatewayReferenceId'];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/v1/charges/' . $transactionId, [], $this->getRequestHeaders());
            // Mocked Response
            $mockStatus = 'SUCCEEDED'; $mockMerchantOrderId = 'ORDER' . strtoupper(uniqid());
             if ($transactionId === 'fail_verify_ref') {
                $mockStatus = 'FAILED';
            }
            $response = ['body' => [
                    'transactionId' => $transactionId,
                    'merchantOrderId' => $mockMerchantOrderId,
                    'status' => $mockStatus, // e.g. SUCCEEDED, FAILED, PENDING, AUTHORIZED
                    'transactionAmount' => [
                        'amount' => sprintf('%.2f', $sanitizedData['original_amount_for_test'] ?? 100.00),
                        'currency' => 'USD' // Assuming USD
                    ],
                    'message' => 'Transaction details retrieved successfully.'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || empty($response['body']['status'])) {
                throw new VerificationException('American Express: Failed to verify. ' . ($response['body']['errors'][0]['message'] ?? 'API error'));
            }

            $paymentStatus = $response['body']['status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'SUCCEEDED' || strtoupper($paymentStatus) === 'CAPTURED' || strtoupper($paymentStatus) === 'AUTHORIZED';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'American Express verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['transactionId'],
                'orderId' => $response['body']['merchantOrderId'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('American Express: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Original Amex transactionId
            throw new RefundException('American Express: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('American Express: Invalid or missing amount for refund.');
        }

        $originalTransactionId = $sanitizedData['transactionId'];
        $payload = [
            'transactionAmount' => [
                'amount' => sprintf('%.2f', $sanitizedData['amount']),
                'currency' => strtoupper($sanitizedData['currency'] ?? 'USD') // Must match original or be supported by Amex
            ],
            'reason' => $sanitizedData['reason'] ?? 'Customer requested refund',
            // 'merchantRefundId' => 'YOUR_UNIQUE_REFUND_ID' // Optional
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/charges/' . $originalTransactionId . '/refunds', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('American Express: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'refundId' => 'AMEXREFUND' . strtoupper(uniqid()),
                    'originalTransactionId' => $originalTransactionId,
                    'status' => 'SUCCEEDED', // Or PENDING
                    'message' => 'Refund processed successfully.'
                ],
                'status_code' => 201
            ];

            if ($response['status_code'] >= 300 || !in_array(strtoupper($response['body']['status'] ?? ''), ['SUCCEEDED', 'PENDING'])) {
                throw new RefundException('American Express: Failed to process refund. ' . ($response['body']['errors'][0]['message'] ?? 'API Error'));
            }
            
            $refundStatus = $response['body']['status'];
            return [
                'status' => strtoupper($refundStatus) === 'SUCCEEDED' ? 'success' : 'pending',
                'message' => 'American Express refund status: ' . $refundStatus,
                'refundId' => $response['body']['refundId'] ?? null,
                'paymentStatus' => $refundStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('American Express: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 