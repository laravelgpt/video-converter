<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class OmantelGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.omantel.om/payment'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.omantel.om/payment'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'apiKey' => '', 
            'apiSecret' => '', // Or a secret key for signing
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/omantel/callback',
            'timeout' => 45,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'apiKey', 'apiSecret'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Omantel: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $params): string
    {
        // Placeholder: Omantel signature logic (e.g., HMAC-SHA256)
        ksort($params);
        $stringToSign = http_build_query($params);
        return hash_hmac('sha256', $stringToSign, $this->config['apiSecret']);
    }

    private function getRequestHeaders(?string $accessToken = null): array
    {
        $headers = [
            'Content-Type' => 'application/json',
            'X-Merchant-ID' => $this->config['merchantId'],
        ];
        if ($accessToken) { // If Omantel uses Bearer tokens for API calls
             $headers['Authorization'] = 'Bearer ' . $accessToken;
        } else { // Or directly use API key in header
            $headers['X-API-KEY'] = $this->config['apiKey'];
        }
        return $headers;
    }
    
    // Mock an access token retrieval if Omantel API uses OAuth
    private function getAccessToken(): string 
    {
        if ($this->config['apiKey'] === 'force_token_error') {
            throw new InitializationException("Omantel: Failed to obtain access token (simulated).");
        }
        return 'mock_omantel_access_token_' . uniqid();
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Omantel: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Omantel: Missing orderId.');
        }

        // $accessToken = $this->getAccessToken(); // If token based auth

        $payload = [
            'merchantTransactionId' => $sanitizedData['orderId'],
            'amount' => [
                'value' => sprintf('%.3f', $sanitizedData['amount']), // OMR often uses 3 decimal places
                'currency' => $sanitizedData['currency'] ?? 'OMR',
            ],
            'description' => $sanitizedData['description'] ?? 'Payment for order ' . $sanitizedData['orderId'],
            'redirectUrl' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            // ... other Omantel specific parameters (e.g. customer info, service type)
        ];
        // $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/initiate', $payload, $this->getRequestHeaders(/*$accessToken*/));
            // Mocked Response
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('Omantel: API rejected initialization (simulated).');
            }
            $mockOmantelTxnId = 'OMANTELTXN' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/redirect/' . $mockOmantelTxnId;
            
            $response = ['body' => [
                    'status' => 'PENDING_REDIRECT',
                    'message' => 'Payment initiated, redirect customer.',
                    'transactionId' => $mockOmantelTxnId,
                    'paymentGatewayUrl' => $mockPaymentUrl
                ],
                'status_code' => 201 // Or 200
            ];

            if ($response['status_code'] >= 300 || strtoupper($response['body']['status'] ?? '') !== 'PENDING_REDIRECT') {
                throw new InitializationException('Omantel: Failed to initialize payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Omantel payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['transactionId'],
                'paymentUrl' => $response['body']['paymentGatewayUrl'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Omantel: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data); // Data from Omantel callback
        // Verify callback integrity (e.g., signature or by re-querying)

        if (empty($sanitizedData['transactionId'])) {
            throw new ProcessingException('Omantel: Missing transactionId in callback.');
        }

        $status = $sanitizedData['paymentStatus'] ?? 'FAILURE'; // e.g. SUCCESS, FAILURE, PENDING_CONFIRMATION
        $isSuccess = strtoupper($status) === 'SUCCESS' || strtoupper($status) === 'COMPLETED';

        // It's often best to call verify() here to get the authoritative status from Omantel server
        // return $this->verify(['gatewayReferenceId' => $sanitizedData['transactionId']]);

        return [
            'status' => $isSuccess ? 'success' : (strtoupper($status) === 'PENDING_CONFIRMATION' ? 'pending' : 'failed'),
            'message' => 'Omantel payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['transactionId'],
            'orderId' => $sanitizedData['merchantTransactionId'] ?? null,
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // Omantel's transactionId
            throw new VerificationException('Omantel: Missing gatewayReferenceId for verification.');
        }
        $transactionId = $sanitizedData['gatewayReferenceId'];
        // $accessToken = $this->getAccessToken(); // If token based auth

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/status/' . $transactionId, [], $this->getRequestHeaders(/*$accessToken*/));
            // Mocked Response
            $mockStatus = 'COMPLETED'; $mockMerchantTxnId = 'ORDER' . strtoupper(uniqid());
             if ($transactionId === 'fail_verify_ref') {
                $mockStatus = 'FAILED';
            }
            $response = ['body' => [
                    'transactionId' => $transactionId,
                    'merchantTransactionId' => $mockMerchantTxnId,
                    'status' => $mockStatus, // e.g. COMPLETED, PENDING, FAILED, CANCELLED
                    'amount' => [
                        'value' => $sanitizedData['original_amount_for_test'] ?? '10.000',
                        'currency' => 'OMR'
                    ],
                    'message' => 'Transaction status retrieved'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || empty($response['body']['status'])) {
                throw new VerificationException('Omantel: Failed to verify payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $paymentStatus = $response['body']['status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'COMPLETED' || strtoupper($paymentStatus) === 'SUCCESS';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Omantel verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['transactionId'],
                'orderId' => $response['body']['merchantTransactionId'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Omantel: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Omantel's transactionId
            throw new RefundException('Omantel: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Omantel: Invalid or missing amount for refund.');
        }
        // $accessToken = $this->getAccessToken(); // If token based auth

        $payload = [
            'originalTransactionId' => $sanitizedData['transactionId'],
            'amount' => [
                'value' => sprintf('%.3f', $sanitizedData['amount']),
                'currency' => $sanitizedData['currency'] ?? 'OMR',
            ],
            'reason' => $sanitizedData['reason'] ?? 'Customer request',
            'merchantRefundId' => 'REFUND_'.($sanitizedData['orderId'] ?? $sanitizedData['transactionId'])
        ];
        // $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/refund', $payload, $this->getRequestHeaders(/*$accessToken*/));
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('Omantel: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'status' => 'REFUND_INITIATED',
                    'message' => 'Refund request accepted',
                    'refundTransactionId' => 'OMANREFUND' . strtoupper(uniqid()),
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || !in_array(strtoupper($response['body']['status'] ?? ''), ['REFUND_INITIATED', 'REFUND_SUCCESSFUL', 'REFUND_PROCESSED'])) {
                throw new RefundException('Omantel: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $refundApiStatus = $response['body']['status'];
            $isSuccess = strtoupper($refundApiStatus) === 'REFUND_SUCCESSFUL' || strtoupper($refundApiStatus) === 'REFUND_PROCESSED';
            $isPending = strtoupper($refundApiStatus) === 'REFUND_INITIATED';

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Omantel refund status: ' . $refundApiStatus,
                'refundId' => $response['body']['refundTransactionId'] ?? null,
                'paymentStatus' => $refundApiStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Omantel: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 