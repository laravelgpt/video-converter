<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class BkashGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://tokenized.sandbox.bka.sh/v1.2.0-beta'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://tokenized.pay.bka.sh/v1.2.0-beta'; // Example

    // Store the token - in a real app, this might need caching/refresh logic
    private ?string $idToken = null;

    protected function getDefaultConfig(): array
    {
        return [
            'appKey' => '',
            'appSecret' => '',
            'username' => '',
            'password' => '',
            'isSandbox' => true,
            'timeout' => 30,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['appKey', 'appSecret', 'username', 'password'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("bKash: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Simulate getting an authentication token from bKash.
     * In a real scenario, this would make an API call.
     */
    private function getAuthToken(): string
    {
        if ($this->idToken) {
            // Potentially add token expiry check here and refresh if needed
            return $this->idToken;
        }

        $payload = [
            'app_key' => $this->config['appKey'],
            'app_secret' => $this->config['appSecret'],
            // bKash uses username/password in a different call, then app_key/app_secret for token
            // This is a simplified mock.
        ];

        // $headers = ['username' => $this->config['username'], 'password' => $this->config['password']];
        // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/token/grant', $payload, $headers);

        // Mocked response
        if ($this->config['appKey'] === 'force_token_error') {
             throw new InitializationException("bKash: Failed to acquire auth token (simulated error).");
        }
        $this->idToken = 'mock_bkash_id_token_' . uniqid();
        return $this->idToken;
    }

    private function getRequestHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'Authorization' => $this->getAuthToken(),
            'X-App-Key' => $this->config['appKey'],
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('bKash: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('bKash: Missing orderId.');
        }
        // bKash requires `intent` (e.g., 'sale') and `paymentID` for execution after creation.
        // `mode` 0011 for tokenized checkout
        $payload = [
            'mode' => '0011', // Tokenized checkout
            'payerReference' => $sanitizedData['payerReference'] ?? '0', // Typically mobile number or other identifier
            'callbackURL' => $sanitizedData['callbackUrl'] ?? ($this->config['defaultCallbackUrl'] ?? 'https://example.com/bkash/callback'),
            'amount' => (string)$sanitizedData['amount'],
            'currency' => 'BDT',
            'intent' => 'sale', // or 'authorization'
            'merchantInvoiceNumber' => $sanitizedData['orderId'],
            // 'merchantAssociationInfo' => 'MI_INFO_STRING' // Optional
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/checkout/create', $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($sanitizedData['amount'] == 999) { // Simulate an error condition
                 throw new InitializationException('bKash: API rejected initialization (simulated).');
            }
            $mockBkashPaymentID = 'mock_bkash_trx_' . uniqid();
            $mockPaymentUrl = ($this->config['isSandbox'] ? 'https://sandbox.bkash.com/redirect/token=' : 'https://pay.bkash.com/redirect/token=') . $mockBkashPaymentID;
            
            $response = ['body' => [
                    'paymentID' => $mockBkashPaymentID,
                    'bkashURL' => $mockPaymentUrl,
                    'statusCode' => '0000', 
                    'statusMessage' => 'Initiated'
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['statusCode'] ?? '') !== '0000') {
                throw new InitializationException('bKash: Failed to create payment. API Error: ' . ($response['body']['statusMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action', // bKash requires user to complete payment on their page
                'message' => 'bKash payment initialized. Redirect user to bKash.',
                'gatewayReferenceId' => $response['body']['paymentID'],
                'paymentUrl' => $response['body']['bkashURL'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('bKash: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Process is typically a callback/webhook handler for bKash.
     * This method could be used to execute a payment if you have paymentID and intent 'sale'.
     * For this example, we assume it's a query/verification or a webhook confirmation.
     */
    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        // For bKash, `process` usually means handling the callback after user payment
        // or executing a previously created payment.
        // We'll treat this as a payment status query for simplicity here, similar to verify.
        if (empty($sanitizedData['paymentID'])) {
            throw new ProcessingException('bKash: Missing paymentID for processing/verification.');
        }
        return $this->verify($sanitizedData); 
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['paymentID'])) {
            throw new VerificationException('bKash: Missing paymentID for verification.');
        }

        $payload = ['paymentID' => $sanitizedData['paymentID']];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/checkout/payment/status', $payload, $this->getRequestHeaders());
            // Mocked response
            $mockStatus = 'Completed'; $mockStatusCode = '0000'; $trxID = 'TRX' . strtoupper(uniqid());
            if (($sanitizedData['paymentID'] ?? '') === 'fail_verify') {
                $mockStatus = 'Failed'; $mockStatusCode = '1002'; $trxID = null;
            }
            
            $response = ['body' => [
                    'trxID' => $trxID,
                    'transactionStatus' => $mockStatus,
                    'statusCode' => $mockStatusCode,
                    'statusMessage' => 'Payment ' . $mockStatus
                ], 
                'status_code' => 200
            ];


            if ($response['status_code'] !== 200) {
                throw new VerificationException('bKash: Failed to verify payment. HTTP Error.');
            }
            
            $apiStatusCode = $response['body']['statusCode'] ?? 'Unknown';
            $paymentStatus = $response['body']['transactionStatus'] ?? 'Unknown';

            if ($apiStatusCode !== '0000' && $apiStatusCode !== '0010' && $apiStatusCode !== '0011') { // 0000=completed, 0010=initiated, 0011=pending
                // Consider other non-success but non-error codes as pending or failed based on transactionStatus
                 // For this mock, treat non-0000 as potentially not successful for simplicity unless explicitly pending
                 if (strtoupper($paymentStatus) !== 'COMPLETED' && strtoupper($paymentStatus) !== 'AUTHORIZED' && strtoupper($paymentStatus) !== 'PENDING') {
                    throw new VerificationException('bKash: Verification failed. API Status: ' . $paymentStatus . ' (' . $apiStatusCode . ')');
                 }
            }

            $isSuccess = strtoupper($paymentStatus) === 'COMPLETED' || strtoupper($paymentStatus) === 'AUTHORIZED';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'bKash verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['trxID'] ?? null,
                'paymentStatus' => $paymentStatus,
                'apiStatusCode' => $apiStatusCode,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('bKash: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['paymentID'])) {
            throw new RefundException('bKash: Missing paymentID for refund.');
        }
        if (empty($sanitizedData['transactionId'])) {
            throw new RefundException('bKash: Missing transactionId (trxID from bKash) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('bKash: Invalid or missing amount for refund.');
        }

        $payload = [
            'paymentID' => $sanitizedData['paymentID'],
            'trxID' => $sanitizedData['transactionId'],
            'amount' => (string)$sanitizedData['amount'],
            'reason' => $sanitizedData['reason'] ?? 'User requested refund',
            'sku' => $sanitizedData['sku'] ?? 'N/A', // Stock Keeping Unit, can be item details
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/checkout/payment/refund', $payload, $this->getRequestHeaders());
            // Mocked response
            $response = ['body' => [
                'refundTrxID' => 'REF' . strtoupper(uniqid()), 
                'transactionStatus' => 'Completed', 
                'statusCode' => '0000', 
                'statusMessage' => 'Refund successful'
                ], 
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['statusCode'] ?? '') !== '0000') {
                throw new RefundException('bKash: Failed to process refund. API Error: ' . ($response['body']['statusMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success',
                'message' => 'bKash refund processed successfully.',
                'refundId' => $response['body']['refundTrxID'] ?? null,
                'paymentStatus' => $response['body']['transactionStatus'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('bKash: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 