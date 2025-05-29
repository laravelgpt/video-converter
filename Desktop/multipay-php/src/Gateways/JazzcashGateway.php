<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class JazzcashGateway extends PaymentGateway
{
    // JazzCash has different integration methods (HTTP POST, Mobile SDK, API)
    // This mock focuses on HTTP POST to their payment page.
    private const API_BASE_URL_SANDBOX = 'https://sandbox.jazzcash.com.pk/CustomerPortal/transactionmanagement'; // Example form post URL
    private const API_BASE_URL_PRODUCTION = 'https://payments.jazzcash.com.pk/CustomerPortal/transactionmanagement'; // Example form post URL
    // Direct API endpoints (e.g., for refunds or status check) might be different.

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',     // pp_MerchantID
            'password' => '',       // pp_Password
            'integritySalt' => '',  // For pp_SecureHash
            'returnUrl' => 'https://example.com/jazzcash/callback', // pp_ReturnURL
            'isSandbox' => true,
            'language' => 'EN',     // pp_Language
            'currency' => 'PKR',    // pp_TxnCurrency
            'version' => '1.1',    // Or 2.0 for newer integrations
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'password', 'integritySalt', 'returnUrl'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("JazzCash: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        // This URL is typically for the form POST to JazzCash payment page.
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Generate JazzCash Secure Hash (pp_SecureHash).
     * String to hash is specific, usually sorted values of certain fields concatenated with salt at the beginning.
     */
    private function generateSecureHash(array $params): string
    {
        // Example string to hash: Salt&Val1&Val2&Val3...
        // The order of parameters in $params matters for constructing the string.
        // Consult JazzCash documentation for the exact fields and their order for hashing.
        // For version 1.1, it's often: Salt & Amount & BillReference & Description & Language & MerchantID & Password & ReturnURL & TxnCurrency & TxnDateTime & TxnExpiryDateTime & TxnRefNumber & Version & SubMerchantID (if any) & BankID (if any) & ProductID (if any) & TxnType (if any)
        
        $stringToHash = $this->config['integritySalt'];
        // Values must be taken from the $params array in the specific order JazzCash dictates.
        // This is a simplified example, ensure correct order and fields based on JazzCash docs.
        $orderedKeysForHash = [
            'pp_Amount', 'pp_BillReference', 'pp_Description', 'pp_Language', 'pp_MerchantID',
            'pp_Password', 'pp_ReturnURL', 'pp_TxnCurrency', 'pp_TxnDateTime', 
            'pp_TxnExpiryDateTime', 'pp_TxnRefNo', 'pp_Version'
            // Add other optional fields like pp_SubMerchantID, pp_BankID, pp_ProductID, pp_TxnType if used.
        ]; 

        foreach ($orderedKeysForHash as $key) {
            if (isset($params[$key]) && $params[$key] !== '') {
                $stringToHash .= "&" . $params[$key];
            }
        }
        return hash_hmac('sha256', $stringToHash, $this->config['integritySalt']);
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('JazzCash: Invalid or missing amount. Amount in PKR, no decimals for JazzCash form post (integer).');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('JazzCash: Missing orderId (pp_TxnRefNo).');
        }

        $txnRefNo = $sanitizedData['orderId']; // Your unique transaction reference number
        $amount = (int) ($sanitizedData['amount'] * 100); // JazzCash requires amount in paisa as integer (e.g. 100.00 PKR is 10000)
        $txnDateTime = date('YmdHis'); // Format: YYYYMMDDHHMMSS
        $txnExpiryDateTime = date('YmdHis', strtotime('+1 hour')); // Example: 1 hour expiry

        $payload = [
            'pp_Version' => $this->config['version'],
            'pp_TxnType' => $sanitizedData['txnType'] ?? 'MWALLET', // MWALLET, MPAY, JazzCash_Tabeer, etc or leave empty for JazzCash page choice
            'pp_Language' => $this->config['language'],
            'pp_MerchantID' => $this->config['merchantId'],
            'pp_Password' => $this->config['password'], 
            'pp_TxnRefNo' => $txnRefNo,
            'pp_Amount' => $amount, // Amount in paisa
            'pp_TxnCurrency' => $this->config['currency'],
            'pp_TxnDateTime' => $txnDateTime,
            'pp_BillReference' => $sanitizedData['billReference'] ?? $txnRefNo, // e.g., invoice number
            'pp_Description' => $sanitizedData['description'] ?? 'Payment for order ' . $txnRefNo,
            'pp_TxnExpiryDateTime' => $txnExpiryDateTime,
            'pp_ReturnURL' => $this->config['returnUrl'],
            // Optional fields:
            // 'pp_SecureHash' => '', // Calculated below
            // 'ppmpf_1' => $sanitizedData['customField1'] ?? null, // Custom fields
            // 'ppmpf_2' => $sanitizedData['customField2'] ?? null,
            // ... up to ppmpf_5
        ];
        
        // Filter out null values before hashing if JazzCash expects that
        // $hashablePayload = array_filter($payload, fn($value) => $value !== null);
        // SecureHash must be calculated on parameters in specific order provided by Jazzcash
        $payload['pp_SecureHash'] = $this->generateSecureHash($payload);

        try {
            if ($amount == 99900) { // Simulating an error if amount is 999 PKR
                 throw new InitializationException('JazzCash: API rejected initialization (simulated for amount 999).');
            }
            $paymentUrl = $this->getApiBaseUrl(); // URL for form POST

            return [
                'status' => 'pending_user_action',
                'message' => 'JazzCash payment requires redirection. Submit the form provided.',
                'paymentUrl' => $paymentUrl,
                'formData' => $payload,
                'gatewayReferenceId' => $txnRefNo,
                'rawData' => ['formAction' => $paymentUrl, 'formFields' => $payload]
            ];
        } catch (\Exception $e) {
            throw new InitializationException('JazzCash: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for JazzCash means handling the callback (POST data from JazzCash to pp_ReturnURL).
        $sanitizedData = $this->sanitize($data); // Data from JazzCash callback (e.g., $_POST)

        // JazzCash response parameters: pp_ResponseCode, pp_ResponseMessage, pp_TxnRefNo, pp_Amount, pp_TxnDateTime, pp_SecureHash, etc.
        if (empty($sanitizedData['pp_ResponseCode']) || empty($sanitizedData['pp_TxnRefNo'])) {
            throw new ProcessingException('JazzCash: Invalid callback data. Missing pp_ResponseCode or pp_TxnRefNo.');
        }

        // $receivedHash = $sanitizedData['pp_SecureHash'] ?? '';
        // $paramsForHashVerification = $sanitizedData; unset($paramsForHashVerification['pp_SecureHash']);
        // $calculatedHash = $this->generateSecureHash($paramsForHashVerification); // Ensure correct params & order for response hash
        // if (strtoupper($receivedHash) !== strtoupper($calculatedHash)) {
        //     throw new ProcessingException('JazzCash: Callback secure hash mismatch.');
        // }

        $responseCode = $sanitizedData['pp_ResponseCode'];
        $isSuccess = $responseCode === '000'; // '000' for success, other codes for failure/pending

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'JazzCash payment processed. Response: ' . ($sanitizedData['pp_ResponseMessage'] ?? 'N/A') . ' (Code: ' . $responseCode . ')',
            'transactionId' => $sanitizedData['pp_RetrivalReferenceNo'] ?? null, // JazzCash's actual transaction ID
            'orderId' => $sanitizedData['pp_TxnRefNo'],
            'amount' => isset($sanitizedData['pp_Amount']) ? ($sanitizedData['pp_Amount'] / 100) : null, // Amount is in paisa
            'paymentStatus' => $responseCode,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // pp_TxnRefNo
            throw new VerificationException('JazzCash: Missing orderId (pp_TxnRefNo) for verification.');
        }
        // JazzCash might not have a standard server-to-server verification API readily available for all integrations.
        // Often, the post-back (process method) is the primary means of verification if hash matches.
        // This is a conceptual placeholder if such an API exists.
        // For now, we'll simulate by checking the orderId pattern.

        try {
            $mockRespCode = '000'; $mockRespMsg = 'Transaction Successful'; $mockRetRefNo = 'JCASHTXN' . strtoupper(uniqid());
            if ($sanitizedData['orderId'] === 'fail_verify') {
                $mockRespCode = '124'; $mockRespMsg = 'Transaction Failed'; $mockRetRefNo = null;
            } else if ($sanitizedData['orderId'] === 'pending_verify'){
                $mockRespCode = '111'; $mockRespMsg = 'Transaction Pending'; // Example pending
            }

            $responseBody = [
                'pp_ResponseCode' => $mockRespCode,
                'pp_ResponseMessage' => $mockRespMsg,
                'pp_TxnRefNo' => $sanitizedData['orderId'],
                'pp_RetrivalReferenceNo' => $mockRetRefNo,
                'pp_Amount' => ($sanitizedData['original_amount_for_test'] ?? 100) * 100, // paisa
                'pp_TxnCurrency' => $this->config['currency']
            ];
            
            $paymentRespCode = $responseBody['pp_ResponseCode'];
            $isSuccess = $paymentRespCode === '000';
            $isPending = in_array($paymentRespCode, ['111', '101']); // Example pending codes

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'JazzCash (simulated) verification: ' . ($responseBody['pp_ResponseMessage'] ?? 'N/A'),
                'transactionId' => $responseBody['pp_RetrivalReferenceNo'] ?? null,
                'orderId' => $responseBody['pp_TxnRefNo'] ?? null,
                'paymentStatus' => $paymentRespCode,
                'rawData' => $responseBody
            ];
        } catch (\Exception $e) {
            throw new VerificationException('JazzCash: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // JazzCash refund process can be complex and might require a separate API integration or manual process via their portal.
        // This is a highly conceptual mock.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // JazzCash RetrivalReferenceNo or original TxnRefNo + Date
            throw new RefundException('JazzCash: Missing transaction identifier for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('JazzCash: Invalid or missing amount for refund.');
        }

        $payload = [
            'pp_Version' => $this->config['version'],
            'pp_TxnType' => 'REFUND', // Or specific refund transaction type
            'pp_MerchantID' => $this->config['merchantId'],
            'pp_Password' => $this->config['password'],
            'pp_TxnRefNo' => 'REFUND_' . ($sanitizedData['orderId'] ?? $sanitizedData['transactionId']), // New unique ref for refund
            'pp_Amount' => (int)($sanitizedData['amount'] * 100),
            'pp_TxnCurrency' => $this->config['currency'],
            'pp_TxnDateTime' => date('YmdHis'),
            'pp_TxnExpiryDateTime' => date('YmdHis', strtotime('+1 hour')),
            'pp_BillReference' => $sanitizedData['originalTxnRefNo'] ?? $sanitizedData['transactionId'], // Original txn reference
            'pp_Description' => $sanitizedData['reason'] ?? 'Refund issued',
            'pp_ReturnURL' => $this->config['returnUrl'] . '/refund-callback', // Separate callback for refund if applicable
        ];
        // $payload['pp_SecureHash'] = $this->generateSecureHash($payload);

        try {
            if ($payload['pp_Amount'] == 99900) { 
                 throw new RefundException('JazzCash: API rejected refund (simulated).');
            }
            // Mocked Response for a conceptual refund API
            $responseBody = [
                'pp_ResponseCode' => '000',
                'pp_ResponseMessage' => 'Refund Initiated Successfully',
                'pp_TxnRefNo' => $payload['pp_TxnRefNo'], // Refund txn ref no
                'pp_RetrivalReferenceNo' => 'JCREFUND' . strtoupper(uniqid()),
            ];

            if ($responseBody['pp_ResponseCode'] !== '000') {
                throw new RefundException('JazzCash: Failed to process refund. API Error: ' . ($responseBody['pp_ResponseMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success', // Or 'pending' if refunds are not immediate
                'message' => 'JazzCash refund status: ' . ($responseBody['pp_ResponseMessage'] ?? ''),
                'refundId' => $responseBody['pp_RetrivalReferenceNo'] ?? $payload['pp_TxnRefNo'],
                'paymentStatus' => $responseBody['pp_ResponseCode'],
                'rawData' => $responseBody
            ];
        } catch (\Exception $e) {
            throw new RefundException('JazzCash: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 