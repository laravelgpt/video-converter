<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class BinancePayGateway extends PaymentGateway
{
    private const API_BASE_URL_PRODUCTION = 'https://bpay.binanceapi.com'; // Example URL
    private const API_BASE_URL_SANDBOX = 'https://bpay.binanceapi.com/sandbox'; // Example URL

    protected function getDefaultConfig(): array
    {
        return [
            'apiKey' => '',
            'secretKey' => '',
            'isSandbox' => true,
            'timeout' => 30, // seconds
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['apiKey'])) {
            throw new InvalidConfigurationException('BinancePay: API Key is required.');
        }
        if (empty($config['secretKey'])) {
            throw new InvalidConfigurationException('BinancePay: Secret Key is required.');
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }
    
    private function generateSignature(array $payload): string
    {
        // IMPORTANT: Implement actual Binance Pay signature generation logic.
        // This is a placeholder and insecure.
        // Typically involves sorting parameters, concatenating with secret key, and hashing (e.g., HMAC-SHA256).
        ksort($payload);
        $stringToSign = http_build_query($payload);
        return hash_hmac('sha256', $stringToSign, $this->config['secretKey']);
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        // Example: Validate required fields for initialization
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('BinancePay: Invalid or missing amount for initialization.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('BinancePay: Missing orderId for initialization.');
        }

        $payload = [
            'merchantId' => $this->config['apiKey'],
            'orderId' => $sanitizedData['orderId'],
            'amount' => $sanitizedData['amount'],
            'currency' => $sanitizedData['currency'] ?? 'USDT',
            'timestamp' => time() * 1000, // Binance often requires milliseconds
            // ... other required parameters by Binance Pay API for initialization
        ];
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/binancepay/openapi/order', $payload, ['Content-Type' => 'application/json']);
            // Mocking response for now
            if ($sanitizedData['amount'] == 999) { // Simulate an error condition
                 throw new InitializationException('BinancePay: API rejected initialization (simulated).');
            }
            $response = ['body' => ['status' => 'SUCCESS', 'data' => ['prepayId' => 'mock_prepay_id_'.uniqid(), 'qrCodeUrl' => 'https://example.com/qr/'.uniqid()]], 'status_code' => 200];


            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new InitializationException('BinancePay: Failed to initialize payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success',
                'message' => 'Binance Pay initialized successfully.',
                'gatewayReferenceId' => $response['body']['data']['prepayId'] ?? null,
                'paymentUrl' => $response['body']['data']['qrCodeUrl'] ?? null, // Or redirect URL
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            // Log the exception: error_log($e->getMessage());
            throw new InitializationException('BinancePay: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        // Processing often happens client-side after initialization or via webhooks.
        // This method might be used for server-to-server notifications or specific post-payment actions.
        // For now, let's assume it confirms a payment based on a transaction ID from Binance.
        if (empty($sanitizedData['transactionId'])) {
            throw new ProcessingException('BinancePay: Missing transactionId for processing.');
        }

        // Simulate direct processing if needed, or this could be a webhook handler
        return [
            'status' => 'success',
            'message' => 'Binance Pay payment processed (simulated confirmation).',
            'transactionId' => $sanitizedData['transactionId'],
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId']) && empty($sanitizedData['gatewayReferenceId'])) {
            throw new VerificationException('BinancePay: Missing orderId or gatewayReferenceId for verification.');
        }

        $payload = [
            'merchantId' => $this->config['apiKey'],
            'timestamp' => time() * 1000,
        ];
        if (!empty($sanitizedData['orderId'])) {
            $payload['merchantTradeNo'] = $sanitizedData['orderId'];
        }
        // Or use gatewayReferenceId (prepayId) if Binance supports it for query
        // else if (!empty($sanitizedData['gatewayReferenceId'])) {
        //    $payload['prepayId'] = $sanitizedData['gatewayReferenceId'];
        // }
        
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/binancepay/openapi/queryorder', $payload, ['Content-Type' => 'application/json']);
            // Mocking response
            $mockStatus = 'PAID';
            if (($sanitizedData['orderId'] ?? '') === 'fail_verify') {
                $mockStatus = 'PENDING';
            }

            $response = ['body' => ['status' => 'SUCCESS', 'data' => ['tradeState' => $mockStatus, 'transactionId' => 'mock_tx_'.uniqid()]], 'status_code' => 200];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new VerificationException('BinancePay: Failed to verify payment. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            $paymentStatus = $response['body']['data']['tradeState'] ?? 'UNKNOWN'; // e.g., PAID, PENDING, FAILED

            return [
                'status' => strtolower($paymentStatus) === 'paid' ? 'success' : 'pending',
                'message' => 'Binance Pay verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['data']['transactionId'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('BinancePay: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) {
            throw new RefundException('BinancePay: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('BinancePay: Invalid or missing amount for refund.');
        }

        $payload = [
            'merchantId' => $this->config['apiKey'],
            'transactionId' => $sanitizedData['transactionId'], // This might be Binance's transaction ID
            'refundAmount' => $sanitizedData['amount'],
            'refundReason' => $sanitizedData['reason'] ?? 'User requested refund',
            'timestamp' => time() * 1000,
            // ... other required parameters by Binance Pay API for refund
        ];
        $payload['signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/binancepay/openapi/refundorder', $payload, ['Content-Type' => 'application/json']);
            // Mocking response
            $response = ['body' => ['status' => 'SUCCESS', 'data' => ['refundId' => 'mock_refund_id_'.uniqid()]], 'status_code' => 200];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new RefundException('BinancePay: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success',
                'message' => 'Binance Pay refund processed successfully.',
                'refundId' => $response['body']['data']['refundId'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('BinancePay: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 