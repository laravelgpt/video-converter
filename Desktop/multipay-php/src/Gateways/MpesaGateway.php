<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class MpesaGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://sandbox.safaricom.co.ke';
    private const API_BASE_URL_PRODUCTION = 'https://api.safaricom.co.ke'; // Or custom, e.g., live.safaricom.co.ke

    protected function getDefaultConfig(): array
    {
        return [
            'consumerKey' => '',        // Your M-Pesa Daraja API Consumer Key
            'consumerSecret' => '',    // Your M-Pesa Daraja API Consumer Secret
            'shortCode' => '',         // Business Shortcode (Paybill or Till Number)
            'passkey' => '',           // Lipa Na M-Pesa Online Passkey (for STK Push)
            'transactionType' => 'CustomerPayBillOnline', // Or CustomerBuyGoodsOnline
            'isSandbox' => true,
            'timeout' => 60,
            'defaultCallbackUrl' => 'https://example.com/mpesa/callback', // Generic callback
            'defaultQueueTimeoutUrl' => 'https://example.com/mpesa/timeout', // For C2B timeout
        ];
    }

    protected function validateConfig(array $config): void
    {
        $requiredKeys = ['consumerKey', 'consumerSecret', 'shortCode', 'passkey', 'transactionType'];
        foreach ($requiredKeys as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("M-Pesa: {$key} is required.");
            }
        }
        if (!in_array($config['transactionType'], ['CustomerPayBillOnline', 'CustomerBuyGoodsOnline'])) {
            throw new InvalidConfigurationException("M-Pesa: Invalid transactionType. Must be CustomerPayBillOnline or CustomerBuyGoodsOnline.");
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function getAccessToken(): string
    {
        // In a real scenario, you'd cache this token until it expires.
        $credentials = base64_encode($this->config['consumerKey'] . ':' . $this->config['consumerSecret']);
        $url = $this->getApiBaseUrl() . '/oauth/v1/generate?grant_type=client_credentials';
        $headers = ['Authorization' => 'Basic ' . $credentials];

        try {
            // $response = $this->httpClient('GET', $url, [], $headers);
            // Mocked Response
            if ($this->config['consumerKey'] === 'FAIL_TOKEN') {
                throw new \Exception('Failed to get M-Pesa access token (simulated auth failure).');
            }
            $mockResponseBody = ['access_token' => 'MOCK_MPESA_ACCESS_TOKEN_' . uniqid(), 'expires_in' => '3599'];
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || empty($response['body']['access_token'])) {
                throw new \Exception('Failed to retrieve M-Pesa access token. Response: ' . json_encode($response['body']));
            }
            return $response['body']['access_token'];
        } catch (\Exception $e) {
            // Log error appropriately
            throw new InitializationException('M-Pesa: Could not retrieve access token. ' . $e->getMessage(), 0, $e);
        }
    }

    private function generateStkPassword(string $timestamp): string
    {
        return base64_encode($this->config['shortCode'] . $this->config['passkey'] . $timestamp);
    }

    public function initialize(array $data): array
    {
        // This typically initiates an STK Push.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] < 1) {
            throw new InitializationException('M-Pesa: Invalid or missing amount. Must be a positive number.');
        }
        if (empty($sanitizedData['phone'])) {
            throw new InitializationException('M-Pesa: Missing phone number (MSISDN) for STK Push.');
        }
        // Phone number should be in Safaricom format e.g. 2547XXXXXXXX
        $phoneNumber = preg_replace('/[^0-9]/','', $sanitizedData['phone']);
        if (strlen($phoneNumber) < 9) { // Basic validation
             throw new InitializationException('M-Pesa: Invalid phone number format.');
        }
        // Ensure it starts with 254 if it's a full international number, or prepend if local 07... format
        if (strpos($phoneNumber, '254') !== 0) {
            if (strpos($phoneNumber, '0') === 0) {
                $phoneNumber = '254' . substr($phoneNumber, 1);
            } else { // Assume it's 7... and prepend 254
                $phoneNumber = '254' . $phoneNumber;
            }
        }
        if (strlen($phoneNumber) !== 12) { // 254 + 9 digits
            throw new InitializationException('M-Pesa: Invalid phone number length after formatting. Expected format 2547XXXXXXXX.');
        }

        if (empty($sanitizedData['orderId'])) { // AccountReference
            throw new InitializationException('M-Pesa: Missing orderId (AccountReference).');
        }

        $timestamp = date('YmdHis');
        $password = $this->generateStkPassword($timestamp);
        $accessToken = $this->getAccessToken();

        $payload = [
            'BusinessShortCode' => $this->config['shortCode'],
            'Password' => $password,
            'Timestamp' => $timestamp,
            'TransactionType' => $this->config['transactionType'],
            'Amount' => round($sanitizedData['amount']), // M-Pesa expects whole numbers
            'PartyA' => $phoneNumber, // Customer phone number
            'PartyB' => $this->config['shortCode'],
            'PhoneNumber' => $phoneNumber, // Customer phone number
            'CallBackURL' => $sanitizedData['callbackUrl'] ?? $this->config['defaultCallbackUrl'],
            'AccountReference' => $sanitizedData['orderId'],
            'TransactionDesc' => $sanitizedData['description'] ?? ('Payment for order ' . $sanitizedData['orderId'])
        ];

        try {
            // $url = $this->getApiBaseUrl() . '/mpesa/stkpush/v1/processrequest';
            // $headers = ['Authorization' => 'Bearer ' . $accessToken, 'Content-Type' => 'application/json'];
            // $response = $this->httpClient('POST', $url, $payload, $headers);
            // Mocked Response
            if ($payload['Amount'] == 9999) {
                 throw new InitializationException('M-Pesa STK Push: API rejected request (simulated error amount).');
            }
            $mockResponseBody = [
                'MerchantRequestID' => 'MOCK_MRID_' . strtoupper(uniqid()),
                'CheckoutRequestID' => 'MOCK_CRID_' . strtoupper(uniqid()),
                'ResponseCode' => '0',
                'ResponseDescription' => 'Success. Request accepted for processing',
                'CustomerMessage' => 'Success. Request accepted for processing'
            ];
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || ($response['body']['ResponseCode'] ?? '-1') !== '0') {
                throw new InitializationException('M-Pesa STK Push failed. Error: ' . ($response['body']['ResponseDescription'] ?? ($response['body']['errorMessage'] ?? 'Unknown API error')));
            }

            return [
                'status' => 'pending_user_confirmation', // User needs to confirm on their phone
                'message' => 'M-Pesa STK Push initiated. User needs to enter PIN on their phone. Response: ' . $response['body']['CustomerMessage'],
                'merchantRequestId' => $response['body']['MerchantRequestID'],
                'checkoutRequestId' => $response['body']['CheckoutRequestID'],
                'orderId' => $sanitizedData['orderId'],
                'gatewayReferenceId' => $response['body']['CheckoutRequestID'], // Use CheckoutRequestID for tracking
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('M-Pesa: STK Push initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This processes the callback from M-Pesa after an STK Push or C2B payment.
        // The $data here is the JSON payload sent by M-Pesa to your callback URL.
        $sanitizedData = $this->sanitize($data); // M-Pesa sends a somewhat nested structure for STK callback

        // STK Push Callback has a Body -> stkCallback structure
        if (isset($sanitizedData['Body']['stkCallback'])) {
            $stkCallback = $sanitizedData['Body']['stkCallback'];
            $merchantRequestId = $stkCallback['MerchantRequestID'] ?? null;
            $checkoutRequestId = $stkCallback['CheckoutRequestID'] ?? null;
            $resultCode = (string)($stkCallback['ResultCode'] ?? '-1');
            $resultDesc = $stkCallback['ResultDesc'] ?? 'No description';

            if (!$merchantRequestId || !$checkoutRequestId) {
                throw new ProcessingException('M-Pesa Callback: Invalid STK callback data. Missing request IDs.');
            }

            $status = 'failed';
            $transactionId = null;
            $amount = null;
            $phone = null;

            if ($resultCode === '0') {
                $status = 'success';
                // CallbackMetadata contains Item array with Name and Value
                if (isset($stkCallback['CallbackMetadata']['Item'])) {
                    foreach ($stkCallback['CallbackMetadata']['Item'] as $item) {
                        if ($item['Name'] === 'MpesaReceiptNumber') {
                            $transactionId = $item['Value'];
                        }
                        if ($item['Name'] === 'Amount') {
                            $amount = $item['Value'];
                        }
                         if ($item['Name'] === 'PhoneNumber') {
                            $phone = $item['Value'];
                        }
                    }
                }
                if (!$transactionId) {
                     // This can happen if the transaction is successful but M-Pesa is slow to provide the receipt number in this specific callback.
                     // It might be better to rely on query API or a subsequent callback if M-Pesa has one for final confirmation.
                     // For this mock, we'll treat it as success but note the missing ID.
                     $message = 'M-Pesa STK payment successful (ResultCode 0), but MpesaReceiptNumber not found in this callback. Query status separately.';
                } else {
                    $message = 'M-Pesa STK payment successful: ' . $resultDesc;
                }
            } else {
                // Handle other M-Pesa error codes appropriately, e.g., user cancelled, insufficient funds, etc.
                $message = 'M-Pesa STK payment failed: ' . $resultDesc . ' (Code: ' . $resultCode . ')';
            }

            return [
                'status' => $status,
                'message' => $message,
                'transactionId' => $transactionId, // MpesaReceiptNumber
                'gatewayReferenceId' => $checkoutRequestId,
                'merchantRequestId' => $merchantRequestId,
                'orderId' => null, // OrderId is not directly in STK callback, needs to be retrieved based on CheckoutRequestID
                'paymentStatus' => $resultCode, 
                'amount' => $amount,
                'phone' => $phone,
                'rawData' => $stkCallback
            ];
        } 
        // Add handling for C2B callback (direct payment to Paybill/Till) if needed. It has a different structure.
        // Example C2B fields: TransactionType, TransID, TransTime, TransAmount, BusinessShortCode, BillRefNumber (orderId), MSISDN etc.
        elseif (isset($sanitizedData['TransID'])) { // Likely a C2B callback
             $status = 'success'; // Assume C2B are successful if callback is received and validated
             $message = 'M-Pesa C2B payment received.';
             return [
                'status' => $status,
                'message' => $message,
                'transactionId' => $sanitizedData['TransID'],
                'orderId' => $sanitizedData['BillRefNumber'] ?? null, // AccountReference from STK or BillRefNumber from C2B
                'amount' => $sanitizedData['TransAmount'] ?? null,
                'phone' => $sanitizedData['MSISDN'] ?? null,
                'paymentStatus' => 'C2B_CONFIRMED', // Custom status
                'rawData' => $sanitizedData
            ];
        }
        
        throw new ProcessingException('M-Pesa Callback: Unknown callback format or missing critical data.');
    }

    public function verify(array $data): array
    {
        // M-Pesa Transaction Status Query API.
        $sanitizedData = $this->sanitize($data);
        // Typically query by CheckoutRequestID (from STK Push init) or original MerchantRequestID.
        // Or, query by TransactionID (MpesaReceiptNumber) if known.
        $checkoutRequestId = $sanitizedData['checkoutRequestId'] ?? ($sanitizedData['gatewayReferenceId'] ?? null);

        if (empty($checkoutRequestId)) {
            throw new VerificationException('M-Pesa: checkoutRequestId is required for transaction status query.');
        }

        $accessToken = $this->getAccessToken();
        $timestamp = date('YmdHis');
        // Password for query API might be different or not needed if using Bearer token with appropriate permissions.
        // For STK Push Query, it uses the same password as STK push.
        $password = $this->generateStkPassword($timestamp); 

        $payload = [
            'BusinessShortCode' => $this->config['shortCode'],
            'Password' => $password,
            'Timestamp' => $timestamp,
            'CheckoutRequestID' => $checkoutRequestId
        ];

        try {
            // $url = $this->getApiBaseUrl() . '/mpesa/stkpushquery/v1/query';
            // $headers = ['Authorization' => 'Bearer ' . $accessToken, 'Content-Type' => 'application/json'];
            // $response = $this->httpClient('POST', $url, $payload, $headers);
            // Mocked Response
            if ($checkoutRequestId === 'MOCK_CRID_FAILQUERY') {
                 throw new VerificationException('M-Pesa Query: API rejected request (simulated).');
            }
            $mockResponseBody = [];
            if ($checkoutRequestId === 'MOCK_CRID_SUCCESS') {
                $mockResponseBody = [
                    'ResponseCode' => '0',
                    'ResponseDescription' => 'The service request is processed successfully.',
                    'MerchantRequestID' => 'MOCK_MRID_FROMQUERY',
                    'CheckoutRequestID' => $checkoutRequestId,
                    'ResultCode' => '0',
                    'ResultDesc' => 'The service request is processed successfully.'
                    // Actual successful transaction details (Amount, MpesaReceiptNumber, etc.) are NOT in this direct query response for STK.
                    // They come via async callback. This query just confirms if the STK push itself was accepted.
                    // A real-world scenario might require storing callback data and using that for true verification.
                ];
            } elseif ($checkoutRequestId === 'MOCK_CRID_PENDING'){
                 $mockResponseBody = [
                    'ResponseCode' => '0', 'ResponseDescription' => 'Request processing', 
                    'MerchantRequestID' => 'MOCK_MRID_PENDING', 'CheckoutRequestID' => $checkoutRequestId, 
                    'ResultCode' => '1037', 'ResultDesc' => 'Timeout in completing transaction' // Example pending/timeout
                ];
            } else { // Simulating a failed transaction in query
                 $mockResponseBody = [
                    'ResponseCode' => '0', 'ResponseDescription' => 'Processed', 
                    'MerchantRequestID' => 'MOCK_MRID_FAILED', 'CheckoutRequestID' => $checkoutRequestId, 
                    'ResultCode' => '1032', 'ResultDesc' => 'Request cancelled by user'
                ];
            }

            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || ($response['body']['ResponseCode'] ?? '-1') !== '0') {
                throw new VerificationException('M-Pesa Query failed. API Error: ' . ($response['body']['errorMessage'] ?? ($response['body']['ResponseDescription'] ?? 'Unknown error')));
            }

            $resultCode = (string)($response['body']['ResultCode'] ?? '-1');
            $resultDesc = $response['body']['ResultDesc'] ?? 'No description from query.';
            $currentStatus = 'failed';

            if ($resultCode === '0') {
                $currentStatus = 'success'; // Query indicates success, but actual Mpesa receipt should be checked from callback data
            } elseif (in_array($resultCode, ['1037'])) { // Example: Timeout is pending
                $currentStatus = 'pending';
            }
            // Any other resultCode from query is usually a failure of the STK process itself or a final failed state.

            return [
                'status' => $currentStatus,
                'message' => 'M-Pesa (simulated query) status: ' . $resultDesc . ' (ResultCode: ' . $resultCode . ')',
                'transactionId' => null, // MpesaReceiptNumber is not available from this STK query API
                'gatewayReferenceId' => $response['body']['CheckoutRequestID'],
                'merchantRequestId' => $response['body']['MerchantRequestID'],
                'paymentStatus' => $resultCode,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('M-Pesa: Transaction status query failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // M-Pesa B2C (Business to Customer) or Reversal API would be used for refunds.
        // This is a complex process, often requiring pre-approval or specific B2C product setup.
        // For this mock, we will simulate a conceptual refund attempt.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Original MpesaReceiptNumber
            // Note: Reversals use TransactionID. B2C might not directly need original TXN ID for refunding a customer.
            throw new RefundException('M-Pesa: transactionId (MpesaReceiptNumber) is often needed for reversals, or customer phone for B2C.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('M-Pesa: Invalid or missing amount for refund.');
        }
        if (empty($sanitizedData['phone'])) { // Customer phone for B2C
             throw new RefundException('M-Pesa: Customer phone number is required for B2C refund.');
        }

        // For Reversal: uses TransactionID, Amount, ReceiverParty (ShortCode), RecieverIdentifierType (e.g. 11 for paybill)
        // For B2C: uses OriginatorConversationID, Amount, PartyB (phone), Remarks, Occasion, CallBackURL, QueueTimeOutURL
        // This mock will loosely simulate a B2C call structure.
        
        $accessToken = $this->getAccessToken();
        $originatorConversationID = 'MOCK_OCID_REFUND_' . strtoupper(uniqid());

        $payload = [
            'OriginatorConversationID' => $originatorConversationID,
            'InitiatorName' => $this->config['initiatorName'] ?? 'apitest', // Registered Initiator Name for B2C
            'SecurityCredential' => $this->config['securityCredential'] ?? 'MOCK_SECURITY_CRED', // Generated from Initiator Password
            'CommandID' => 'BusinessPayment', // Or SalaryPayment, PromotionPayment
            'Amount' => round($sanitizedData['amount']),
            'PartyA' => $this->config['shortCode'], // Organization's shortcode
            'PartyB' => $sanitizedData['phone'], // Customer MSISDN
            'Remarks' => $sanitizedData['reason'] ?? 'Refund for order',
            'QueueTimeOutURL' => $this->config['defaultQueueTimeoutUrl'],
            'ResultURL' => $this->config['defaultCallbackUrl'],
            'Occasion' => $sanitizedData['occasion'] ?? 'Refund'
        ];
        
        try {
            // $url = $this->getApiBaseUrl() . '/mpesa/b2c/v1/paymentrequest';
            // $headers = ['Authorization' => 'Bearer ' . $accessToken, 'Content-Type' => 'application/json'];
            // $response = $this->httpClient('POST', $url, $payload, $headers);
            // Mocked Response
            if ($payload['Amount'] == 999) {
                 throw new RefundException('M-Pesa B2C: API rejected refund (simulated amount).');
            }
             $mockResponseBody = [
                'OriginatorConversationID' => $originatorConversationID,
                'ConversationID' => 'MOCK_CONVID_B2C_' . strtoupper(uniqid()),
                'ResponseCode' => '0',
                'ResponseDescription' => 'Accept the request for processing'
            ];
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || ($response['body']['ResponseCode'] ?? '-1') !== '0') {
                throw new RefundException('M-Pesa B2C refund initiation failed. Error: ' . ($response['body']['ResponseDescription'] ?? ($response['body']['errorMessage'] ?? 'Unknown API error')));
            }

            // B2C is asynchronous. Actual success/failure comes via callback to ResultURL.
            return [
                'status' => 'pending',
                'message' => 'M-Pesa B2C refund request accepted for processing. Final status via callback. Desc: ' . $response['body']['ResponseDescription'],
                'refundId' => $originatorConversationID, // Use OriginatorConversationID as a reference
                'gatewayReferenceId' => $response['body']['ConversationID'], // M-Pesa's ConversationID for this B2C transaction
                'paymentStatus' => 'REFUND_INITIATED',
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('M-Pesa: B2C Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 