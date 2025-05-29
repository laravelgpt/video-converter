<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class NagadGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://sandbox.mynagad.com'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.mynagad.com'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'merchantPrivateKey' => '',
            'nagadPublicKey' => '', // Nagad's public key for encrypting sensitive data
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/nagad/callback',
            'timeout' => 30,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'merchantPrivateKey', 'nagadPublicKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Nagad: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Mock encryption of sensitive data with Nagad's public key.
     */
    private function encryptWithNagadPublicKey(string $data): string
    {
        // In a real scenario, use OpenSSL functions for RSA encryption.
        // openssl_public_encrypt($data, $encrypted, $this->config['nagadPublicKey'], OPENSSL_PKCS1_PADDING);
        if ($this->config['nagadPublicKey'] === 'force_encrypt_error') {
            return ''; // Simulate encryption failure
        }
        return "encrypted(" . base64_encode($data) . ")";
    }

    /**
     * Mock decryption of callback data with merchant's private key.
     */
    private function decryptWithMerchantPrivateKey(string $encryptedData): string
    {
        // In a real scenario, use OpenSSL functions for RSA decryption.
        // openssl_private_decrypt(base64_decode($encryptedData), $decrypted, $this->config['merchantPrivateKey'], OPENSSL_PKCS1_PADDING);
        if (strpos($encryptedData, 'encrypted(') === 0) {
            return base64_decode(substr($encryptedData, strlen('encrypted('), -1));
        }
        if ($this->config['merchantPrivateKey'] === 'force_decrypt_error'){
            return '';
        }
        return "decryption_failed_or_invalid_data";
    }
    
    /**
     * Mock signing data with merchant's private key.
     */
    private function signData(string $data): string
    {
        // openssl_sign($data, $signature, $this->config['merchantPrivateKey'], OPENSSL_ALGO_SHA256);
        // return base64_encode($signature);
        if ($this->config['merchantPrivateKey'] === 'force_sign_error') {
            return '';
        }
        return "signed(".hash('sha256', $data . $this->config['merchantPrivateKey']).")";
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Nagad: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Nagad: Missing orderId.');
        }

        $dateTime = date('YmdHis');
        $orderId = $sanitizedData['orderId'];
        // Sensitive data that needs to be encrypted
        $sensitiveData = json_encode([
            'merchantId' => $this->config['merchantId'],
            'orderId' => $orderId,
            'amount' => (string)$sanitizedData['amount'],
            'challenge' => bin2hex(random_bytes(16)) // A random challenge
        ]);

        $encryptedSensitiveData = $this->encryptWithNagadPublicKey($sensitiveData);
        if (empty($encryptedSensitiveData)){
            throw new InitializationException('Nagad: Failed to encrypt sensitive data.');
        }
        
        $dataToSign = $this->config['merchantId'] . $orderId . $dateTime; // Example, check Nagad docs
        $signature = $this->signData($dataToSign);
        if (empty($signature)){
            throw new InitializationException('Nagad: Failed to sign request data.');
        }

        $payload = [
            'accountNumber' => $this->config['merchantId'], // Or your merchant mobile number
            'dateTime' => $dateTime,
            'sensitiveData' => $encryptedSensitiveData,
            'signature' => $signature,
            // 'orderId' => $orderId, // Sometimes passed outside sensitive data too
            'merchantCallbackURL' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/api/dfs/check-out/initialize/' . $this->config['merchantId'] . '/' . $orderId, $payload);
            // Mocked response: Nagad initialize usually returns a callId and redirect URL component
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('Nagad: API rejected initialization (simulated).');
            }
            $mockCallId = 'NAGAD_CALLID_' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/check-out?payment_reference=' . $mockCallId . '&sensitive_data=' . urlencode($encryptedSensitiveData) . '&signature=' . urlencode($signature);
            
            $response = ['body' => [
                    'callId' => $mockCallId, 
                    // 'acceptDateTime' => $dateTime,
                    'status' => 'Success', // Nagad API response structure varies
                    'reason' => null
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new InitializationException('Nagad: Failed to initialize payment. API Error: ' . ($response['body']['reason'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Nagad payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['callId'],
                'paymentUrl' => $mockPaymentUrl, // This would be the full Nagad checkout URL
                'rawData' => array_merge($response['body'], ['constructed_url' => $mockPaymentUrl])
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Nagad: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // For Nagad, `process` is usually handling the callback from Nagad after payment attempt.
        // This involves decrypting and verifying the response.
        $sanitizedData = $this->sanitize($data); // Data comes from Nagad callback (query params or POST body)

        if (empty($sanitizedData['payment_ref_id'])) { // This name can vary, check Nagad docs
            throw new ProcessingException('Nagad: Missing payment reference ID in callback.');
        }
        if (empty($sanitizedData['sensitive_data'])) {
            throw new ProcessingException('Nagad: Missing sensitive data in callback.');
        }
        if (empty($sanitizedData['signature'])) {
            throw new ProcessingException('Nagad: Missing signature in callback.');
        }

        // 1. Decrypt sensitive data
        $decryptedDataString = $this->decryptWithMerchantPrivateKey($sanitizedData['sensitive_data']);
        if (empty($decryptedDataString) || $decryptedDataString === "decryption_failed_or_invalid_data"){
            throw new ProcessingException('Nagad: Failed to decrypt callback sensitive data.');
        }
        $callbackDetails = json_decode($decryptedDataString, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ProcessingException('Nagad: Failed to parse decrypted callback data.');
        }

        // 2. Verify signature (simplified - Nagad may require verifying signature of the original data or parts of it)
        // This is a placeholder; actual signature verification is more complex.
        // Typically, you'd verify the signature against the sensitive data or specific fields from it.
        // $dataToVerify = $callbackDetails['merchantId'] . $callbackDetails['orderId'] ... ; // Construct as per Nagad docs
        // if (!$this->verifySignature($dataToVerify, $sanitizedData['signature'])) {
        //     throw new ProcessingException('Nagad: Callback signature verification failed.');
        // }

        $status = $callbackDetails['status'] ?? 'Failed';
        $isSuccess = strtoupper($status) === 'SUCCESS';

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'Nagad payment processed. Status: ' . $status,
            'transactionId' => $callbackDetails['issuer_payment_ref_no'] ?? $sanitizedData['payment_ref_id'],
            'orderId' => $callbackDetails['order_id'] ?? null,
            'amount' => $callbackDetails['amount'] ?? null,
            'paymentStatus' => $status,
            'rawData' => array_merge($sanitizedData, ['decrypted' => $callbackDetails])
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId']) && empty($sanitizedData['gatewayReferenceId'])) {
            throw new VerificationException('Nagad: Missing orderId or gatewayReferenceId (callId) for verification.');
        }

        // Nagad verification requires callId (gatewayReferenceId) or merchantId + orderId
        $orderIdToVerify = $sanitizedData['orderId'] ?? ('ref_' . ($sanitizedData['gatewayReferenceId'] ?? time()));

        $payload = [
            // Payload for verification API - specific to Nagad
            // This might involve merchantId and the orderId or payment_ref_id
        ];
        // $headers = [ ... ];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/api/dfs/verify/payment/' . $orderIdToVerify, [], $headers);
            // Mocked Response
            $mockStatus = 'Success'; $issuerRef = 'NAGAD_TRX_'.strtoupper(uniqid());
            if (($sanitizedData['orderId'] ?? '') === 'fail_verify' || ($sanitizedData['gatewayReferenceId'] ?? '') === 'fail_verify_ref') {
                $mockStatus = 'Failed'; $issuerRef = null;
            }
            
            $response = ['body' => [
                    'merchantId' => $this->config['merchantId'],
                    'orderId' => $orderIdToVerify,
                    'paymentRefId' => $sanitizedData['gatewayReferenceId'] ?? 'PAY_REF_'.uniqid(),
                    'status' => $mockStatus,
                    'issuerPaymentRefNo' => $issuerRef,
                    // ... other fields like amount, clientMobileNo etc.
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200) {
                throw new VerificationException('Nagad: Failed to verify payment. HTTP Error.');
            }

            $paymentStatus = $response['body']['status'] ?? 'Failed';
            $isSuccess = strtoupper($paymentStatus) === 'SUCCESS';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'Nagad verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['issuerPaymentRefNo'] ?? null,
                'orderId' => $response['body']['orderId'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Nagad: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Nagad refund process is typically more complex, often manual or through a separate portal.
        // If an API exists, it would involve similar encryption/signing.
        // For this mock, we'll assume a simple direct refund if possible.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Nagad's issuerPaymentRefNo
            throw new RefundException('Nagad: Missing transactionId (issuerPaymentRefNo) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Nagad: Invalid or missing amount for refund.');
        }

        // Payload for refund API - specific to Nagad, likely involving encrypted data and signature
        $payload = [
            'transactionId' => $sanitizedData['transactionId'],
            'amount' => (string)$sanitizedData['amount'],
            'reason' => $sanitizedData['reason'] ?? 'User request',
            // ... other details, possibly merchantId, orderId, etc.
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/api/dfs/refund', $payload, $headers);
            // Mocked Response
             if ($sanitizedData['amount'] == 999) { // Simulate an error condition
                 throw new RefundException('Nagad: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'status' => 'Success',
                    'refundRefId' => 'NAGAD_REFUND_'.strtoupper(uniqid()),
                    'message' => 'Refund request accepted'
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || strtoupper($response['body']['status'] ?? '') !== 'SUCCESS') {
                throw new RefundException('Nagad: Failed to process refund. API Error: ' . ($response['body']['message'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success', // Or 'pending' if Nagad processes refunds asynchronously
                'message' => 'Nagad refund request processed: ' . ($response['body']['message'] ?? 'Success'),
                'refundId' => $response['body']['refundRefId'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Nagad: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 