<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class MobiKwikGateway extends PaymentGateway
{
    private const API_BASE_URL_STAGING = 'https://test.mobikwik.com'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.mobikwik.com'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'secretKey' => '',
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/mobikwik/callback',
            'timeout' => 45,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'secretKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("MobiKwik: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_STAGING : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Generate MobiKwik checksum. This is highly specific to MobiKwik's requirements.
     * Usually involves specific parameter ordering and concatenation with secret key.
     */
    private function generateChecksum(array $params): string
    {
        // Placeholder: MobiKwik often requires all POST parameters sorted alphabetically by key,
        // then concatenated into a string, and then hashed (e.g., md5 or sha256) with the secret key appended.
        // Example: value1value2value3...secretkey
        // $allParams = '';
        // ksort($params);
        // foreach ($params as $key => $value) {
        //     $allParams .= str_replace("'", "", $value); // Remove single quotes as per some docs
        // }
        // return hash('sha256', $allParams . $this->config['secretKey']); // Or md5, check docs.
        if (($params['orderid'] ?? '') === 'checksum_fail') return 'invalid_checksum';
        return 'mock_mobikwik_checksum_' . hash('md5', json_encode($params) . $this->config['secretKey']);
    }

    private function verifyChecksum(array $params, string $receivedChecksum): bool
    {
        // $generatedChecksum = $this->generateChecksum($params);
        // return $generatedChecksum === $receivedChecksum;
        if ($receivedChecksum === 'invalid_checksum') return false;
        return true; // Mock
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('MobiKwik: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('MobiKwik: Missing orderId.');
        }
        if (empty($sanitizedData['email'])) {
            throw new InitializationException('MobiKwik: Missing email.');
        }
        if (empty($sanitizedData['mobileNumber'])) {
            throw new InitializationException('MobiKwik: Missing mobileNumber.');
        }

        $orderId = $sanitizedData['orderId'];
        $amount = sprintf('%.2f', $sanitizedData['amount']);

        $payload = [
            'email' => $sanitizedData['email'],
            'amount' => $amount,
            'cell' => $sanitizedData['mobileNumber'], // Customer mobile number
            'orderid' => $orderId,
            'mid' => $this->config['merchantId'],
            'redirecturl' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            // 'showmobile' => '1', // For showing mobile number field on page
            // 'version' => '2', // API version if applicable
            // 'merchantname' => 'Your Merchant Name',
        ];
        $payload['checksum'] = $this->generateChecksum($payload);

        try {
            if ($amount == '999.00') { 
                 throw new InitializationException('MobiKwik: API rejected initialization (simulated).');
            }
            $paymentUrl = $this->getApiBaseUrl() . '/wallet/redirect'; // Example endpoint for redirection

            return [
                'status' => 'pending_user_action',
                'message' => 'MobiKwik payment requires user redirection. Submit the form provided.',
                'paymentUrl' => $paymentUrl,
                'formData' => $payload,
                'gatewayReferenceId' => $orderId,
                'rawData' => ['formAction' => $paymentUrl, 'formFields' => $payload]
            ];
        } catch (\Exception $e) {
            throw new InitializationException('MobiKwik: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for MobiKwik means handling the callback.
        $sanitizedData = $this->sanitize($data); // Data is from MobiKwik POST callback

        if (empty($sanitizedData['orderid']) || empty($sanitizedData['statuscode'])) {
            throw new ProcessingException('MobiKwik: Invalid callback data. Missing orderid or statuscode.');
        }

        $receivedChecksum = $sanitizedData['checksum'] ?? '';
        // unset($sanitizedData['checksum']); // Check MobiKwik docs if checksum field itself is part of checksum calculation for response
        // $paramsToVerify = []; // Construct carefully based on what MobiKwik sends back and expects for verification
        // foreach($sanitizedData as $key => $val) { $paramsToVerify[$key] = $val; }
        // if (!$this->verifyChecksum($paramsToVerify, $receivedChecksum)) {
        //     throw new ProcessingException('MobiKwik: Callback checksum mismatch.');
        // }

        $statusCode = $sanitizedData['statuscode'];
        $statusMessage = $sanitizedData['statusmessage'] ?? 'No message';
        $isSuccess = $statusCode === '0'; // '0' usually means success for MobiKwik

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'MobiKwik payment processed. Status: ' . $statusMessage . ' (Code: ' . $statusCode . ')',
            'transactionId' => $sanitizedData['txid'] ?? null, // MobiKwik's transaction ID
            'orderId' => $sanitizedData['orderid'],
            'amount' => $sanitizedData['amount'] ?? null,
            'paymentStatus' => $statusCode,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) {
            throw new VerificationException('MobiKwik: Missing orderId for verification.');
        }

        $payload = [
            'mid' => $this->config['merchantId'],
            'orderid' => $sanitizedData['orderId'],
        ];
        $payload['checksum'] = $this->generateChecksum($payload); // Checksum might be needed for status API

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/wallet/status', $payload, ['Content-Type' => 'application/x-www-form-urlencoded']);
            // Mocked Response
            $mockStatusCode = '0'; $mockStatusMsg = 'Success'; $mockTxId = 'MBKTXN' . strtoupper(uniqid());
            if ($sanitizedData['orderId'] === 'fail_verify') {
                $mockStatusCode = '1'; $mockStatusMsg = 'Failure'; $mockTxId = null;
            } else if ($sanitizedData['orderId'] === 'pending_verify'){
                $mockStatusCode = '2'; $mockStatusMsg = 'Pending';
            }
            
            $response = ['body' => [
                    'statuscode' => $mockStatusCode, 
                    'statusmessage' => $mockStatusMsg,
                    'orderid' => $sanitizedData['orderId'],
                    'txid' => $mockTxId,
                    'amount' => $sanitizedData['original_amount_for_test'] ?? '100.00',
                ],
                'status_code' => 200 // This is a mock wrapper, MobiKwik API might not have this
            ];

            // Check actual response structure of MobiKwik status API.
            if (!isset($response['body']['statuscode'])) {
                throw new VerificationException('MobiKwik: Failed to verify payment. Invalid API response.');
            }

            $paymentStatusCode = $response['body']['statuscode'];
            $isSuccess = $paymentStatusCode === '0';
            $isPending = $paymentStatusCode === '2'; // Example pending code

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'MobiKwik verification result: ' . ($response['body']['statusmessage'] ?? 'N/A'),
                'transactionId' => $response['body']['txid'] ?? null,
                'orderId' => $response['body']['orderid'] ?? null,
                'paymentStatus' => $paymentStatusCode,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('MobiKwik: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // MobiKwik's txid
            throw new RefundException('MobiKwik: Missing transactionId (txid) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('MobiKwik: Invalid or missing amount for refund.');
        }

        $payload = [
            'mid' => $this->config['merchantId'],
            'txid' => $sanitizedData['transactionId'],
            'amount' => sprintf('%.2f', $sanitizedData['amount']),
            // 'refundorderid' => 'YOUR_UNIQUE_REFUND_ID', // Optional, but good practice
        ];
        $payload['checksum'] = $this->generateChecksum($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/wallet/refund', $payload, ['Content-Type' => 'application/x-www-form-urlencoded']);
            // Mocked response
            if ($payload['amount'] == '999.00') { 
                 throw new RefundException('MobiKwik: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'statuscode' => '100', // Refund success, or other codes for pending/failed
                    'statusmessage' => 'Refund Successful',
                    'refundid' => 'MBKREFUND' . strtoupper(uniqid()),
                    'txid' => $sanitizedData['transactionId'],
                ],
                'status_code' => 200
            ];

            if (!isset($response['body']['statuscode']) || $response['body']['statuscode'] !== '100') { // '100' for refund success (example)
                throw new RefundException('MobiKwik: Failed to process refund. API Error: ' . ($response['body']['statusmessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success', // Assume '100' is direct success, adjust if pending states exist
                'message' => 'MobiKwik refund status: ' . ($response['body']['statusmessage'] ?? ''),
                'refundId' => $response['body']['refundid'] ?? null,
                'paymentStatus' => $response['body']['statuscode'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('MobiKwik: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 