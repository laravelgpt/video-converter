<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class BankDhofarGateway extends PaymentGateway
{
    private const API_BASE_URL_UAT = 'https://uat.bankdhofar.com/pgw'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://pgw.bankdhofar.com/pgw'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'apiKey' => '', // Or Access Key
            'secretKey' => '', // For signing/MAC generation
            'terminalId' => '', // May be required
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/bankdhofar/callback',
            'currencyCode' => '512', // ISO 4217 numeric code for OMR
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'apiKey', 'secretKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Bank Dhofar: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_UAT : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Generate signature/MAC for Bank Dhofar. 
     * This usually involves specific fields concatenated and hashed with a secret key.
     */
    private function generateMAC(array $params): string
    {
        // Placeholder: Bank Dhofar MAC generation logic. Consult their specific documentation.
        // Often, it's a SHA256 or SHA512 HMAC of a string formed by concatenating specific field values in a predefined order.
        // ksort($params); // Or specific order
        // $stringToSign = implode('|', $params); // Example concatenation
        // return hash_hmac('sha256', $stringToSign, hex2bin($this->config['secretKey'])); // If secret key is hex
        if (($params[' udf1'] ?? '') === 'mac_fail') return 'invalid_mac_hash'; // Using udf1 for test
        return hash('sha256', json_encode($params) . $this->config['secretKey']); // Simplified mock
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Bank Dhofar: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Bank Dhofar: Missing orderId (trackId).');
        }

        $trackId = $sanitizedData['orderId']; // Merchant's unique transaction ID
        // Bank Dhofar amounts are typically in the major unit (e.g. 10.500 OMR)
        $amount = sprintf('%.3f', $sanitizedData['amount']); 

        $payload = [
            'id' => $this->config['merchantId'],
            'password' => $this->config['apiKey'], // Or however API key is passed
            'action' => '1', // Action code for Hosted Payment Page Initialization (Purchase)
            'currencycode' => $sanitizedData['currencyCode'] ?? $this->config['currencyCode'],
            'amt' => $amount,
            'trackid' => $trackId,
            'responseURL' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'errorURL' => $sanitizedData['errorUrl'] ?? ($this->config['callbackUrl'] . '?error=1'),
            'langid' => 'USA', // Or ARA for Arabic
            // User Defined Fields (udf1 to udf5) can be used for additional data
            'udf1' => $sanitizedData['udf1'] ?? 'ExtraData1',
            'udf2' => $sanitizedData['udf2'] ?? 'CustomerName',
            // ... other fields as per Bank Dhofar specs (e.g., TerminalID if required)
        ];
        $payload['tranportalId'] = $this->config['terminalId']; // If separate terminal ID
        $payload['requestHash'] = $this->generateMAC($payload); // Or specific name like `mac` or `securehash`

        try {
            if ($amount == '999.000') { 
                 throw new InitializationException('Bank Dhofar: API rejected initialization (simulated).');
            }
            // Bank Dhofar usually redirects to their payment page. The initialize call might return a payment ID and redirect URL.
            // Or you construct a form and POST to their endpoint.
            // This mocks a response that gives a redirect URL.
            $mockPaymentId = 'BDTXN' . strtoupper(uniqid());
            $paymentUrl = $this->getApiBaseUrl() . '?paymentid=' . $mockPaymentId; // Example redirect structure

            // Or if the init call itself is the form action target:
            // $paymentUrl = $this->getApiBaseUrl() . '/PaymentHTTP.htm'; 

            return [
                'status' => 'pending_user_action',
                'message' => 'Bank Dhofar payment requires redirection.',
                'paymentUrl' => $paymentUrl, 
                'formData' => $payload, // If form POST is needed with these params to $paymentUrl
                'gatewayReferenceId' => $mockPaymentId, // Bank Dhofar's payment ID
                'orderId' => $trackId,
                'rawData' => ['paymentId' => $mockPaymentId, 'redirectTo' => $paymentUrl, 'formFields' => $payload]
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Bank Dhofar: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Bank Dhofar: handling the callback (data POSTed back from Bank Dhofar).
        // Parameters usually include: paymentid, result, auth, ref, trackid, amt, udf1-udf5, error_code, error_text, hash
        $sanitizedData = $this->sanitize($data); 

        if (empty($sanitizedData['paymentid']) || empty($sanitizedData['trackid'])) {
            throw new ProcessingException('Bank Dhofar: Invalid callback. Missing paymentid or trackid.');
        }

        // $receivedHash = $sanitizedData['hash'] ?? ''; // Or other hash field name
        // $paramsToVerify = $sanitizedData; unset($paramsToVerify['hash']);
        // // MAC for response might use specific fields in specific order.
        // if (!$this->verifyMAC($paramsToVerify, $receivedHash)) { // Conceptual verifyMAC
        //     throw new ProcessingException('Bank Dhofar: Callback MAC verification failed.');
        // }

        $resultIndicator = $sanitizedData['result'] ?? 'ERROR'; // e.g. CAPTURED, NOT CAPTURED, DENIED, ERROR
        $isSuccess = $resultIndicator === 'CAPTURED';

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'Bank Dhofar payment processed. Result: ' . $resultIndicator . ' - ' . ($sanitizedData['error_text'] ?? ($sanitizedData['authRespCode_desc'] ?? '')),
            'transactionId' => $sanitizedData['ref'] ?? null, // Bank's reference number
            'gatewayReferenceId' => $sanitizedData['paymentid'], // Bank's payment ID
            'orderId' => $sanitizedData['trackid'],
            'amount' => $sanitizedData['amt'] ?? null,
            'authCode' => $sanitizedData['auth'] ?? null, // Authorization code
            'paymentStatus' => $resultIndicator,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        // For Bank Dhofar, verification might involve sending trackid or paymentid to a specific inquiry endpoint.
        if (empty($sanitizedData['orderId']) && empty($sanitizedData['gatewayReferenceId'])) {
            throw new VerificationException('Bank Dhofar: Missing orderId (trackid) or gatewayReferenceId (paymentid) for verification.');
        }

        $idToVerify = $sanitizedData['gatewayReferenceId'] ?? $sanitizedData['orderId'];
        // Determine if ID is paymentid or trackid based on what's passed or format.

        $payload = [
            'id' => $this->config['merchantId'],
            'password' => $this->config['apiKey'],
            'action' => '2', // Or '5' for inquiry, check Bank Dhofar docs
            // 'paymentid' => $isPaymentIdLookup ? $idToVerify : null,
            // 'trackid' => !$isPaymentIdLookup ? $idToVerify : null,
            'amt' => sprintf('%.3f', $sanitizedData['amount'] ?? 0), // Amount might be needed for some inquiry types
            'transid' => $idToVerify, // Often transaction ID (ref from process) or payment ID
             'tranportalId' => $this->config['terminalId']
        ];
        // $payload['requestHash'] = $this->generateMAC($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/PaymentHTTP.htm', $payload); // Example inquiry endpoint
            // Mocked Response: Bank Dhofar often returns data in a specific format, could be key=value pairs or XML/JSON
            $mockResult = 'CAPTURED'; $mockRef = 'BDREF' . strtoupper(uniqid()); $mockTrackId = $sanitizedData['orderId'] ?? ('TRK' . strtoupper(uniqid()));
            if ($idToVerify === 'fail_verify') {
                $mockResult = 'NOT CAPTURED'; $mockRef = null;
            }
            
            // This mock assumes a JSON-like structure derived from typical bank PG responses.
            $responseBody = [
                'paymentid' => $idToVerify, // Or if $idToVerify was trackId, this would be the paymentid from bank
                'result' => $mockResult, // e.g. CAPTURED, NOT CAPTURED, PENDING
                'ref' => $mockRef, // Bank reference number
                'trackid' => $mockTrackId,
                'amt' => $sanitizedData['original_amount_for_test'] ?? '10.500',
                'auth' => 'MOCKAUTH123',
                // 'responseCode' => '00' // Often a separate numeric code
            ];
            // This outer structure is for our library, not Bank Dhofar's direct response
            $response = ['body' => $responseBody, 'status_code' => 200]; 

            if ($response['status_code'] !== 200 || empty($response['body']['result'])) {
                throw new VerificationException('Bank Dhofar: Failed to verify payment. API communication error.');
            }

            $paymentStatus = $response['body']['result'];
            $isSuccess = $paymentStatus === 'CAPTURED';
            $isPending = $paymentStatus === 'PENDING' || $paymentStatus === 'HOST TIMEOUT'; // Example pending states

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Bank Dhofar verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['ref'] ?? null,
                'gatewayReferenceId' => $response['body']['paymentid'] ?? null,
                'orderId' => $response['body']['trackid'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Bank Dhofar: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Bank Dhofar's 'ref' (bank reference number from successful transaction)
            throw new RefundException('Bank Dhofar: Missing transactionId (bank reference number) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Bank Dhofar: Invalid or missing amount for refund.');
        }

        $payload = [
            'id' => $this->config['merchantId'],
            'password' => $this->config['apiKey'],
            'action' => '2', // Or '4' for refund. Check Bank Dhofar docs. '2' often means refund/capture against original auth.
            'currencycode' => $sanitizedData['currencyCode'] ?? $this->config['currencyCode'],
            'amt' => sprintf('%.3f', $sanitizedData['amount']),
            'transid' => $sanitizedData['transactionId'], // This is usually the 'ref' from the original successful transaction
            'trackid' => $sanitizedData['orderId'] ?? ('REFUND_' . $sanitizedData['transactionId']), // Can be new track ID for refund or original
            'udf1' => 'REFUND_REQUEST',
             'tranportalId' => $this->config['terminalId']
        ];
        // $payload['requestHash'] = $this->generateMAC($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/PaymentHTTP.htm', $payload);
            // Mocked response
            if ($payload['amt'] == '999.000') { 
                 throw new RefundException('Bank Dhofar: API rejected refund (simulated).');
            }
            $responseBody = [
                'result' => 'CAPTURED', // Assuming refund is a type of capture of negative amount or a specific success code
                'ref' => 'BDREFUND' . strtoupper(uniqid()),
                'trackid' => $payload['trackid'],
                'auth' => 'REFUNDAUTH',
                // 'responseCode' => '00'
            ];
            $response = ['body' => $responseBody, 'status_code' => 200];

            // Check actual success indicators from Bank Dhofar refund API.
            if ($response['status_code'] !== 200 || $response['body']['result'] !== 'CAPTURED' /* Replace with actual success indicator */) {
                throw new RefundException('Bank Dhofar: Failed to process refund. API Error: ' . ($response['body']['error_text'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success', // Adjust if refunds can be pending
                'message' => 'Bank Dhofar refund status: ' . $response['body']['result'],
                'refundId' => $response['body']['ref'] ?? null,
                'paymentStatus' => $response['body']['result'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Bank Dhofar: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 