<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class UrpayGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.urpay.com'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.urpay.com'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'clientId' => '',
            'clientSecret' => '',
            'terminalId' => '', // Or merchantId
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/urpay/callback',
            'timeout' => 30,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['clientId', 'clientSecret', 'terminalId'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Urpay: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $params): string
    {
        // Placeholder: Urpay signature logic
        ksort($params);
        $stringToSign = http_build_query($params) . $this->config['clientSecret'];
        return hash('sha256', $stringToSign);
    }

    private function getRequestHeaders(?string $accessToken = null): array
    {
        $headers = ['Content-Type' => 'application/json'];
        if ($accessToken) {
            $headers['Authorization'] = 'Bearer ' . $accessToken;
        }
        return $headers;
    }
    
    // Mock an access token retrieval if needed for Urpay
    private function getAccessToken(): string 
    {
        // $payload = ['grant_type' => 'client_credentials', 'client_id' => $this->config['clientId'], 'client_secret' => $this->config['clientSecret']];
        // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/oauth/token', $payload);
        // if ($response['status_code'] !== 200 || empty($response['body']['access_token'])){
        //     throw new InitializationException("Urpay: Failed to obtain access token.");
        // }
        // return $response['body']['access_token'];
        if ($this->config['clientId'] === 'force_token_error') {
            throw new InitializationException("Urpay: Failed to obtain access token (simulated).");
        }
        return 'mock_urpay_access_token_' . uniqid();
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Urpay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Urpay: Missing orderId.');
        }

        $accessToken = $this->getAccessToken(); // Get token first if required by Urpay

        $payload = [
            'TerminalId' => $this->config['terminalId'],
            'OrderId' => $sanitizedData['orderId'],
            'Amount' => $sanitizedData['amount'],
            'Currency' => $sanitizedData['currency'] ?? 'SAR',
            'RedirectUrl' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'Description' => $sanitizedData['description'] ?? 'Payment for order ' . $sanitizedData['orderId'],
            // 'CustomerIp' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            // ... other Urpay specific parameters
        ];
        // $payload['Signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payments/initiate', $payload, $this->getRequestHeaders($accessToken));
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('Urpay: API rejected initialization (simulated).');
            }
            $mockUrpayTxnId = 'URPAYTXN' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/pay/' . $mockUrpayTxnId; // Example structure
            
            $response = ['body' => [
                    'TransactionId' => $mockUrpayTxnId,
                    'PaymentUrl' => $mockPaymentUrl,
                    'ResponseMessage' => 'SUCCESS'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['ResponseMessage'] ?? '') !== 'SUCCESS') {
                throw new InitializationException('Urpay: Failed to initialize payment. API Error: ' . ($response['body']['ResponseMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Urpay payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['TransactionId'],
                'paymentUrl' => $response['body']['PaymentUrl'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Urpay: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data); // Data from Urpay callback
        // Verify callback (e.g., check signature or query parameter `TransactionId`)

        if (empty($sanitizedData['TransactionId'])) {
            throw new ProcessingException('Urpay: Missing TransactionId in callback.');
        }
        // $gatewaySignature = $sanitizedData['Signature']; unset($sanitizedData['Signature']);
        // if ($this->generateSignature($sanitizedData) !== $gatewaySignature) { ... error ... }

        $status = $sanitizedData['Status'] ?? 'FAILURE'; // e.g. SUCCESS, FAILURE, PENDING
        $isSuccess = strtoupper($status) === 'SUCCESS';

        return [
            'status' => $isSuccess ? 'success' : (strtoupper($status) === 'PENDING' ? 'pending' : 'failed'),
            'message' => 'Urpay payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['TransactionId'],
            'orderId' => $sanitizedData['OrderId'] ?? null,
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // Urpay's TransactionId
            throw new VerificationException('Urpay: Missing gatewayReferenceId (TransactionId) for verification.');
        }
        $accessToken = $this->getAccessToken();
        $transactionId = $sanitizedData['gatewayReferenceId'];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/payments/' . $transactionId . '/status', [], $this->getRequestHeaders($accessToken));
            // Mocked Response
            $mockStatus = 'SUCCESS'; $mockOrderId = 'ORDER' . strtoupper(uniqid());
             if ($transactionId === 'fail_verify_ref') {
                $mockStatus = 'FAILURE';
            }
            $response = ['body' => [
                    'TransactionId' => $transactionId,
                    'OrderId' => $mockOrderId,
                    'Status' => $mockStatus, // e.g. SUCCESS, FAILURE, PENDING
                    'Amount' => $sanitizedData['original_amount_for_test'] ?? '100.00',
                    'ResponseMessage' => 'SUCCESS'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['ResponseMessage'] ?? '') !== 'SUCCESS') {
                throw new VerificationException('Urpay: Failed to verify payment. API Error: ' . ($response['body']['ResponseMessage'] ?? 'Unknown error'));
            }

            $paymentStatus = $response['body']['Status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'SUCCESS';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Urpay verification result: ' . $paymentStatus,
                'transactionId' => $transactionId,
                'orderId' => $response['body']['OrderId'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Urpay: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Urpay's TransactionId
            throw new RefundException('Urpay: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Urpay: Invalid or missing amount for refund.');
        }
        $accessToken = $this->getAccessToken();

        $payload = [
            'TransactionId' => $sanitizedData['transactionId'],
            'Amount' => $sanitizedData['amount'],
            'Reason' => $sanitizedData['reason'] ?? 'Customer request',
            'TerminalId' => $this->config['terminalId'],
            // ... other parameters
        ];
        // $payload['Signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payments/refund', $payload, $this->getRequestHeaders($accessToken));
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('Urpay: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'RefundTransactionId' => 'URPAYREFUND' . strtoupper(uniqid()),
                    'Status' => 'SUCCESS',
                    'ResponseMessage' => 'Refund initiated successfully'
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['Status'] ?? '') !== 'SUCCESS') {
                throw new RefundException('Urpay: Failed to process refund. API Error: ' . ($response['body']['ResponseMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success',
                'message' => 'Urpay refund processed successfully.',
                'refundId' => $response['body']['RefundTransactionId'] ?? null,
                'paymentStatus' => $response['body']['Status'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Urpay: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 