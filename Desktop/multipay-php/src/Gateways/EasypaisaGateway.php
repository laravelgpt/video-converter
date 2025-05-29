<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class EasypaisaGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://easypay.sandbox.easypaisa.com.pk'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://easypay.easypaisa.com.pk'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'storeId' => '',
            'hashKey' => '', // Secure Hash Key provided by Easypaisa
            'paymentMethod' => 'MA', // MA (Mobile Account), OTC (Over The Counter), CC (Credit Card), etc.
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/easypaisa/callback', // Post back URL
            'autoRedirect' => '0', // 0 for merchant to handle redirect, 1 for Easypay to auto redirect
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['storeId', 'hashKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Easypaisa: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Generate Easypaisa hash. String to hash is created by concatenating sorted values of specific fields.
     * The exact fields and order are crucial and defined by Easypaisa.
     */
    private function generateRequestHash(array $params): string
    {
        // Example for MA (Mobile Account) or CC (Credit Card)
        // StringToHash = HashKey&amount=value&orderRefNum=value&paymentMethod=value&postBackURL=value&storeId=value
        // This is a simplified placeholder. Consult Easypaisa documentation for the correct fields and order.
        $stringToHash = $this->config['hashKey'];
        $hashParams = [
            'amount' => $params['amount'],
            'orderRefNum' => $params['orderRefNum'],
            'paymentMethod' => $params['paymentMethod'],
            'postBackURL' => $params['postBackURL'],
            'storeId' => $params['storeId']
            // Potentially other fields like `emailAddress`, `mobileNum` depending on payment method and API version
        ];
        ksort($hashParams); // Sort by key, then concatenate values
        foreach($hashParams as $key => $value) {
            $stringToHash .= "&{$key}=" . $value;
        }
        return hash('sha256', $stringToHash); // Or other algorithm specified by Easypaisa
    }
    
    private function verifyResponseHash(array $params, string $receivedHash): bool
    {
        // Response hash calculation can be different. Example: HashKey&amount=value&desc=value&orderRefNum=value&status=value&storeId=value
        // This is a placeholder.
        if ($receivedHash === 'FAIL_HASH') return false;
        return true; // Mock
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Easypaisa: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Easypaisa: Missing orderId (orderRefNum).');
        }

        $orderRefNum = $sanitizedData['orderId'];
        $amount = sprintf('%.2f', $sanitizedData['amount']);

        $payload = [
            'storeId' => $this->config['storeId'],
            'amount' => $amount,
            'postBackURL' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'orderRefNum' => $orderRefNum,
            'paymentMethod' => $sanitizedData['paymentMethod'] ?? $this->config['paymentMethod'],
            'autoRedirect' => $this->config['autoRedirect'],
            'emailAddress' => $sanitizedData['email'] ?? null, 
            'mobileNum' => $sanitizedData['mobileNumber'] ?? null, 
            // 'merchantPaymentMethod' => 'MA/OTC/CC' // Optional field to allow user to choose on Easypay page
            // 'tokenExpiry' // if tokenization is used
            // 'bankIdentificationNumber' // for specific bank offers
        ];
        // Filter out null values before hashing if Easypaisa requires
        $hashablePayload = array_filter($payload, fn($value) => $value !== null && $value !== '');
        $payload['secureHash'] = $this->generateRequestHash($hashablePayload);

        try {
            if ($amount == '999.00') { 
                 throw new InitializationException('Easypaisa: API rejected initialization (simulated).');
            }
            // Easypaisa typically requires a form POST to their endpoint
            $paymentUrl = $this->getApiBaseUrl() . '/easypay/Index.jsf'; // Example endpoint
            if ($this->config['paymentMethod'] === 'MA_TestAPI') { // Conceptual direct API endpoint
                $paymentUrl = $this->getApiBaseUrl() . '/easypay/v4/MAvoucherReq';
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Easypaisa payment requires redirection. Submit the form provided.',
                'paymentUrl' => $paymentUrl, // URL for form POST
                'formData' => $payload,    // Data for the form
                'gatewayReferenceId' => $orderRefNum,
                'rawData' => ['formAction' => $paymentUrl, 'formFields' => $payload]
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Easypaisa: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Easypaisa means handling the callback (POST from Easypaisa to postBackURL).
        $sanitizedData = $this->sanitize($data); // Data from Easypaisa callback (e.g., $_POST)

        if (empty($sanitizedData['orderRefNumber']) || empty($sanitizedData['responseCode'])) {
            throw new ProcessingException('Easypaisa: Invalid callback data. Missing orderRefNumber or responseCode.');
        }
        // $receivedHash = $sanitizedData['secureHashValue'] ?? '';
        // $paramsToVerify = [ /* construct based on Easypaisa docs for response hash */ ];
        // if (!$this->verifyResponseHash($paramsToVerify, $receivedHash)) {
        //     throw new ProcessingException('Easypaisa: Callback hash verification failed.');
        // }

        $responseCode = $sanitizedData['responseCode'];
        $isSuccess = $responseCode === '0000'; // '0000' for success, other codes for failure/pending

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'Easypaisa payment processed. Response: ' . ($sanitizedData['desc'] ?? 'N/A') . ' (Code: ' . $responseCode . ')',
            'transactionId' => $sanitizedData['transactionId'] ?? ($sanitizedData['ibftransid'] ?? null), // Easypaisa's transaction ID
            'orderId' => $sanitizedData['orderRefNumber'],
            'amount' => $sanitizedData['amount'] ?? null,
            'paymentStatus' => $responseCode,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // orderRefNum
            throw new VerificationException('Easypaisa: Missing orderId (orderRefNum) for verification.');
        }

        $payload = [
            'storeId' => $this->config['storeId'],
            'orderRefNum' => $sanitizedData['orderId'],
            // 'accountNum' => 'Optional if checking MA transaction for specific number'
        ];
        // Some inquiry APIs might require hash as well.
        // $payload['secureHash'] = $this->generateRequestHash($payload); 

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/easypay/v4/inquirePayment', $payload); // Example inquiry endpoint
            // Mocked Response
            $mockRespCode = '0000'; $mockRespDesc = 'Transaction Successful'; $mockTxnId = 'EPAYTXN' . strtoupper(uniqid());
            if ($sanitizedData['orderId'] === 'fail_verify') {
                $mockRespCode = '0001'; $mockRespDesc = 'Transaction Failed'; $mockTxnId = null;
            } else if ($sanitizedData['orderId'] === 'pending_verify'){
                $mockRespCode = '0002'; $mockRespDesc = 'Transaction Pending';
            }
            
            $response = ['body' => [
                    'responseCode' => $mockRespCode,
                    'responseDesc' => $mockRespDesc,
                    'orderRefNum' => $sanitizedData['orderId'],
                    'transactionId' => $mockTxnId,
                    'amount' => $sanitizedData['original_amount_for_test'] ?? '100.00',
                    'storeId' => $this->config['storeId']
                ],
                'status_code' => 200 // Mocked wrapper
            ];

            if (!isset($response['body']['responseCode'])) {
                throw new VerificationException('Easypaisa: Failed to verify payment. Invalid API response.');
            }

            $paymentRespCode = $response['body']['responseCode'];
            $isSuccess = $paymentRespCode === '0000';
            $isPending = $paymentRespCode === '0002'; // Example pending code

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Easypaisa verification result: ' . ($response['body']['responseDesc'] ?? 'N/A'),
                'transactionId' => $response['body']['transactionId'] ?? null,
                'orderId' => $response['body']['orderRefNum'] ?? null,
                'paymentStatus' => $paymentRespCode,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Easypaisa: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Easypaisa's transactionId
            throw new RefundException('Easypaisa: Missing transactionId for refund.');
        }
        if (empty($sanitizedData['orderId'])) { 
            throw new RefundException('Easypaisa: Missing orderId (original orderRefNum) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Easypaisa: Invalid or missing amount for refund.');
        }

        $payload = [
            'storeId' => $this->config['storeId'],
            'transactionId' => $sanitizedData['transactionId'],
            'orderRefNum' => $sanitizedData['orderId'],
            'refundAmount' => sprintf('%.2f', $sanitizedData['amount']),
            // 'emailAddress' => 'customer_email_for_notification', // Optional
        ];
        // $payload['secureHash'] = $this->generateRequestHash($payload); // Hash for refund API

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/easypay/v4/refundTransaction', $payload);
            // Mocked response
            if ($payload['refundAmount'] == '999.00') { 
                 throw new RefundException('Easypaisa: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'responseCode' => '0000', // Refund success code
                    'responseDesc' => 'Refund initiated successfully',
                    'refundReqId' => 'EPAYREFUND' . strtoupper(uniqid()),
                    'transactionId' => $sanitizedData['transactionId']
                ],
                'status_code' => 200 // Mocked wrapper
            ];

            if (!isset($response['body']['responseCode']) || $response['body']['responseCode'] !== '0000') {
                throw new RefundException('Easypaisa: Failed to process refund. API Error: ' . ($response['body']['responseDesc'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success', // Assume '0000' is direct success
                'message' => 'Easypaisa refund status: ' . ($response['body']['responseDesc'] ?? ''),
                'refundId' => $response['body']['refundReqId'] ?? null,
                'paymentStatus' => $response['body']['responseCode'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Easypaisa: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 