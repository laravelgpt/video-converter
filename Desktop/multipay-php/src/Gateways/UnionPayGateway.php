<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class UnionPayGateway extends PaymentGateway
{
    // UnionPay UPOP (UnionPay Online Payment) / QuickPass URLs - these are highly regional and product-specific
    // Example for international gateway (might need to be adjusted based on specific integration)
    private const API_BASE_URL_SANDBOX = 'https://gateway.test.unionpayintl.com'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://gateway.unionpayintl.com'; // Example

    // Front-end transaction request URL (for redirect/form post)
    private const FRONT_TRANS_URL_PATH = '/frontTransReq.do';
    // Back-end transaction request URL (for S2S calls like query, refund)
    private const BACK_TRANS_URL_PATH = '/backTransReq.do';
    // App transaction request URL
    private const APP_TRANS_URL_PATH = '/appTransReq.do';


    protected function getDefaultConfig(): array
    {
        return [
            'merId' => '',             // Your UnionPay Merchant ID
            'signCertPath' => '',      // Path to your .pfx or .pem merchant private key certificate for signing
            'signCertPassword' => '',  // Password for your sign certificate
            'encryptCertPath' => '',   // Path to UnionPay's public key certificate .cer for encrypting sensitive data (e.g. card number for S2S)
            'verifyCertPathDir' => '', // Directory containing UnionPay's root and intermediate .cer certificates for verifying signatures
            'isSandbox' => true,
            'timeout' => 60,
            'version' => '5.1.0',     // API Version (e.g., 5.0.0, 5.1.0)
            'encoding' => 'UTF-8',
            'signMethod' => '01',     // Signature Method: 01 for RSA SHA256 (recommended). Older might use SHA1.
            'txnType' => '01',        // Transaction Type: 01 (Consume), 02 (Pre-auth), 04 (Refund), etc.
            'bizType' => '000201',    // Business Type: e.g., 000201 for standard B2C online payment
            'channelType' => '07',    // Channel Type: 05 (Mobile App), 07 (PC Web), 08 (Mobile Web)
            'accessType' => '0',      // Access Type: 0 (Merchant direct), 1 (Acquirer), 2 (PSP)
            'frontUrl' => 'https://example.com/unionpay/return', // Synchronous return URL
            'backUrl' => 'https://example.com/unionpay/notify',  // Asynchronous notification URL
        ];
    }

    protected function validateConfig(array $config): void
    {
        $requiredKeys = ['merId', 'signCertPath', 'signCertPassword', 'verifyCertPathDir'];
        foreach ($requiredKeys as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("UnionPay: {$key} is required.");
            }
        }
        // encryptCertPath is needed if sending sensitive data like card numbers directly (not typical for redirect flows)
    }

    private function getRequestUrl(string $requestPath): string
    {
        $base = $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
        return $base . $requestPath;
    }

    // Conceptual: Generate signature for request parameters
    // This is extremely complex in reality, involving specific data ordering, digesting, and RSA signing with PFX/PEM.
    private function generateSignature(array &$params): void // Pass by reference to add signature to params
    {
        // 1. Filter out 'signature' if present, and empty value parameters.
        // 2. Sort parameters alphabetically by key.
        // 3. Concatenate into query string: key1=value1&key2=value2...
        // 4. Calculate SHA256 (or SHA1 for older versions) digest of the string.
        // 5. Sign the digest using merchant's private key (from PFX/PEM) with RSA.
        // 6. Base64 encode the signature.
        // 7. Add it as 'signature' => $encodedSignature to $params.

        // Simplified Mock:
        if (($params['txnAmt'] ?? 0) == 99999998) { // Amount in cents
            $params['signature'] = 'FAIL_UNIONPAY_SIGN_GENERATION';
            return;
        }
        // Ensure orderId is present for mock signature generation
        $orderIdForSign = $params['orderId'] ?? 'UNKNOWN_ORDER_ID';
        $params['signature'] = 'MOCK_UNIONPAY_SIGNATURE_FOR_' . strtoupper(md5(http_build_query($params) . $orderIdForSign . $this->config['signCertPassword']));
    }

    // Conceptual: Verify signature of UnionPay's notification/response
    // Also very complex, involves using UnionPay's public certificates.
    private function verifySignature(array $params): bool
    {
        $signature = $params['signature'] ?? '';
        if ($signature === 'FAIL_UNIONPAY_SIGN_VERIFY') return false;
        if (empty($signature)) return false; 

        // 1. Extract 'signature' from params.
        // 2. Filter params: remove 'signature', empty values.
        // 3. Sort alphabetically by key.
        // 4. Concatenate into query string.
        // 5. Calculate SHA256 (or SHA1) digest.
        // 6. Decode received signature (Base64).
        // 7. Verify with UnionPay's public key (from .cer files specified in verifyCertPathDir and potentially certId in response).

        // Simplified Mock:
        $tempParams = $params;
        unset($tempParams['signature']);
        $expectedSignature = 'MOCK_UNIONPAY_SIGNATURE_FOR_' . strtoupper(md5(http_build_query($tempParams) . ($params['orderId'] ?? 'UNKNOWN_ORDER_ID') . $this->config['signCertPassword']));
        // For testing, allow specific good signature
        if (isset($params['queryId']) && $signature === 'VALID_SIGN_FOR_QUERYID_'.$params['queryId']) return true;
        
        // return hash_equals($expectedSignature, $signature); // More secure comparison
        // Basic mock: if it looks like our generated one, assume ok for testing.
        return strpos($signature, 'MOCK_UNIONPAY_SIGNATURE_FOR_') === 0;
    }

    private function buildCommonRequestParams(string $txnType, string $bizType): array
    {
        return [
            'version' => $this->config['version'],
            'encoding' => $this->config['encoding'],
            'signMethod' => $this->config['signMethod'],
            'txnType' => $txnType,      // e.g., 01 (Consume), 04 (Refund)
            'txnSubType' => '01',     // Default: 01 (Normal transaction)
            'bizType' => $bizType,      // e.g., 000201 (Standard B2C)
            'channelType' => $this->config['channelType'], // 07 (PC Web), 08 (Mobile Web), 05 (Mobile App)
            'accessType' => $this->config['accessType'],
            'merId' => $this->config['merId'],
            'txnTime' => date('YmdHis'), // YYYYMMDDHHMMSS
            // 'certId' => '...' // Automatically read from PFX by SDK, or provided if multiple certs
        ];
    }

    public function initialize(array $data): array
    {
        // This mock simulates a redirect/form post for PC/Mobile Web payment.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // orderId (merchant order ID)
            throw new InitializationException('UnionPay: Missing orderId.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('UnionPay: Invalid amount. Amount in cents.');
        }

        $params = $this->buildCommonRequestParams($this->config['txnType'], $this->config['bizType']);
        $params['orderId'] = $sanitizedData['orderId'];
        $params['txnAmt'] = (string)round($sanitizedData['amount']); // Amount in cents, as string
        $params['currencyCode'] = $sanitizedData['currencyCode'] ?? '156'; // 156 for CNY
        $params['frontUrl'] = $sanitizedData['returnUrl'] ?? $this->config['frontUrl'];
        $params['backUrl'] = $sanitizedData['notifyUrl'] ?? $this->config['backUrl'];
        // $params['reqReserved'] = 'custom_data_here'; // Optional reserved field

        $this->generateSignature($params);
        if ($params['signature'] === 'FAIL_UNIONPAY_SIGN_GENERATION') {
            throw new InitializationException('UnionPay: Failed to generate request signature (simulated).');
        }

        // Determine URL based on channel (PC/Mobile Web vs App)
        $requestPath = ($params['channelType'] === '05') ? self::APP_TRANS_URL_PATH : self::FRONT_TRANS_URL_PATH;
        $paymentUrl = $this->getRequestUrl($requestPath);

        // For App payments (channelType 05), the response from this initialize step (if it were a real API call)
        // would typically be a `tn` (trade number) to be passed to UnionPay's mobile SDK.
        // For Web payments, we construct a form to auto-POST to UnionPay.

        try {
             if ($params['txnAmt'] == '99999999') { // Simulate API rejection by UnionPay
                 throw new InitializationException('UnionPay: Request rejected by UnionPay (simulated amount error).');
            }

            if ($params['channelType'] === '05') { // App payment
                // Simulate getting a `tn` (trade number) for App SDK
                $mockTn = 'MOCK_UNIONPAY_TN_FOR_' . $params['orderId'] . time();
                return [
                    'status' => 'pending_client_sdk_action',
                    'message' => 'UnionPay App payment initialized. Pass tn to client SDK.',
                    'tn' => $mockTn, // Trade Number for UnionPay Mobile SDK
                    'orderId' => $params['orderId'],
                    'gatewayReferenceId' => null, // UnionPay queryId comes later
                    'rawData' => ['tn' => $mockTn, 'params' => $params]
                ];
            } else { // Web payment (PC or Mobile Web)
                $formHtml = "<form name=\"unionpaysubmit\" method=\"post\" action=\"{$paymentUrl}\">";
                foreach ($params as $key => $val) {
                    $formHtml .= "<input type=\"hidden\" name=\"{$key}\" value=\"" . htmlspecialchars($val) . "\"/>";
                }
                $formHtml .= "<input type=\"submit\" value=\"Submit\" style=\"display:none;\"></form><script>document.forms['unionpaysubmit'].submit();</script>";

                return [
                    'status' => 'pending_user_redirect',
                    'message' => 'UnionPay payment initialized. Auto-submitting form will redirect user.',
                    'htmlForm' => $formHtml,
                    'paymentUrl' => $paymentUrl,
                    'formData' => $params,
                    'orderId' => $params['orderId'],
                    'gatewayReferenceId' => null,
                    'rawData' => ['formAction' => $paymentUrl, 'formFields' => $params]
                ];
            }
        } catch (\Exception $e) {
            if ($e instanceof InitializationException) throw $e;
            throw new InitializationException('UnionPay: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Processes asynchronous notification (POST to backUrl) or synchronous return (POST to frontUrl).
        // $data here is $_POST from UnionPay.
        // Asynchronous notification is more reliable.
        $sanitizedData = $this->sanitize($data);

        if (empty($sanitizedData['orderId']) || !isset($sanitizedData['respCode'])) {
            throw new ProcessingException('UnionPay Callback: Invalid data. Missing orderId or respCode.');
        }

        // Verify signature (CRITICAL for backUrl/notify_url)
        if (!$this->verifySignature($sanitizedData)) {
            // Only strictly fail if proper certs seem to be configured for mock, otherwise allow for basic testing.
            if(!empty($this->config['verifyCertPathDir'])){
                throw new ProcessingException('UnionPay Callback: Signature verification failed.');
            }
        }

        $orderId = $sanitizedData['orderId'];
        $unionPayQueryId = $sanitizedData['queryId'] ?? null; // UnionPay's transaction ID
        $respCode = $sanitizedData['respCode']; // e.g., 00, A6 for success. Others for failure/pending.
        $respMsg = $sanitizedData['respMsg'] ?? '';

        $finalStatus = 'failed';
        $message = 'UnionPay payment status: ' . $respMsg . ' (Code: ' . $respCode . ')';

        if ($respCode === '00' || $respCode === 'A6') {
            $finalStatus = 'success';
        } elseif (in_array($respCode, ['03', '04', '05'])) { // Example codes for pending/processing
            $finalStatus = 'pending';
        }
        // Specific handling for cancellation/rejection based on respCode
        // e.g. '12' (Transaction rejected), '34' (Order not found), etc. can be explicit 'failed' or 'cancelled'
        if ($respCode === '12') { $message = 'UnionPay: Transaction rejected by issuer. (Code: 12)';}
        if ($sanitizedData['user_cancelled_payment'] ?? false) {
            $finalStatus = 'failed'; // or 'cancelled'
            $message = 'UnionPay: User explicitly cancelled the payment (simulated).';
        }

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $unionPayQueryId,
            'orderId' => $orderId,
            'paymentStatus' => $respCode,
            'amount' => isset($sanitizedData['txnAmt']) ? ($sanitizedData['txnAmt']) : null, // Amount in cents
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Transaction Status Query (Uses backTransReq.do endpoint)
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) {
            throw new VerificationException('UnionPay: orderId is required for query.');
        }
        // txnTime of the original transaction can also be required by UnionPay for query
        if (empty($sanitizedData['originalTxnTime'])) { // YYYYMMDDHHMMSS
            // throw new VerificationException('UnionPay: originalTxnTime is required for query.');
        }

        $params = $this->buildCommonRequestParams('00', $this->config['bizType']); // txnType 00 for Query
        $params['orderId'] = $sanitizedData['orderId'];
        $params['txnTime'] = $sanitizedData['originalTxnTime'] ?? $params['txnTime']; // Use original txnTime if provided, else current for query txn itself
        
        $this->generateSignature($params);
        if ($params['signature'] === 'FAIL_UNIONPAY_SIGN_GENERATION') {
            throw new VerificationException('UnionPay Query: Failed to generate request signature (simulated).');
        }

        try {
            // $responseForm = $this->httpClient('POST', $this->getRequestUrl(self::BACK_TRANS_URL_PATH), $params, [], false); // false for form data
            // $response = []; // Parse $responseForm (which is key=value pairs) into an array
            // parse_str($responseForm, $response);
            // Mocked Response:
            $mockResponse = [];
            if ($params['orderId'] === 'FAIL_UNIONPAY_QUERY_API') {
                throw new VerificationException('UnionPay Query: API error (simulated).');
            }

            if ($params['orderId'] === 'ORDER_SUCCESS_UP') {
                $mockResponse = ['origRespCode' => '00', 'origRespMsg' => 'Success', 'queryId' => 'UP_QID_SUCCESS_'.uniqid(), 'orderId' => $params['orderId'], 'txnAmt' => '10000'];
            } elseif ($params['orderId'] === 'ORDER_PENDING_UP') {
                $mockResponse = ['origRespCode' => '03', 'origRespMsg' => 'Processing', 'queryId' => 'UP_QID_PENDING_'.uniqid(), 'orderId' => $params['orderId'], 'txnAmt' => '5000'];
            } elseif ($params['orderId'] === 'ORDER_REJECTED_UP') {
                $mockResponse = ['origRespCode' => '12', 'origRespMsg' => 'Rejected', 'queryId' => 'UP_QID_REJECTED_'.uniqid(), 'orderId' => $params['orderId'], 'txnAmt' => '2000'];
            } else { // Not found or other failure
                $mockResponse = ['origRespCode' => '34', 'origRespMsg' => 'Order not found', 'orderId' => $params['orderId']];
            }
            $mockResponse['respCode'] = '00'; // Query itself was successful
            $mockResponse['signature'] = 'VALID_SIGN_FOR_QUERYID_'.($mockResponse['queryId'] ?? 'tempqid'); // Mock valid signature for query
            $response = $mockResponse;
            // End Mock

            if (!isset($response['respCode']) || $response['respCode'] !== '00') {
                throw new VerificationException('UnionPay Query: Failed. ' . ($response['respMsg'] ?? 'Unknown error from gateway query execution.'));
            }
            // Verify signature of the query response
            if (!$this->verifySignature($response)) {
                 // if(!empty($this->config['verifyCertPathDir'])){
                 //    throw new VerificationException('UnionPay Query: Response signature verification failed.');
                 // }
            }

            $originalRespCode = $response['origRespCode'] ?? '';
            $finalStatus = 'failed';
            if ($originalRespCode === '00' || $originalRespCode === 'A6') {
                $finalStatus = 'success';
            } elseif (in_array($originalRespCode, ['03', '04', '05'])) {
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'UnionPay Query Original Status: ' . ($response['origRespMsg'] ?? $originalRespCode),
                'transactionId' => $response['queryId'] ?? null, // UnionPay's query ID for the original transaction
                'orderId' => $response['orderId'] ?? null,
                'paymentStatus' => $originalRespCode,
                'amount' => isset($response['txnAmt']) ? ($response['txnAmt']) : null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new VerificationException('UnionPay: Transaction query failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Transaction Type 04 for Refund. Uses backTransReq.do.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // Original orderId
            throw new RefundException('UnionPay: Missing original orderId for refund.');
        }
        if (empty($sanitizedData['transactionId'])) { // Original queryId from UnionPay
            throw new RefundException('UnionPay: Missing original transactionId (queryId from UnionPay) for refund.');
        }
        if (empty($sanitizedData['originalTxnTime'])) { // YYYYMMDDHHMMSS of original transaction
            throw new RefundException('UnionPay: Missing originalTxnTime for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('UnionPay: Invalid refund amount.');
        }

        $params = $this->buildCommonRequestParams('04', $this->config['bizType']); // txnType 04 for Refund
        $params['orderId'] = $sanitizedData['refundOrderId'] ?? ('REFUND_' . $sanitizedData['orderId'] . uniqid()); // New orderId for this refund transaction
        $params['txnAmt'] = (string)round($sanitizedData['amount']); // Amount in cents
        $params['currencyCode'] = $sanitizedData['currencyCode'] ?? '156';
        $params['backUrl'] = $this->config['backUrl']; // For refund notification
        $params['origQryId'] = $sanitizedData['transactionId']; // queryId of the original transaction to be refunded
        // $params['origOrderId'] = $sanitizedData['orderId']; // Sometimes original order ID is also sent
        // $params['origTxnTime'] = $sanitizedData['originalTxnTime']; // Sometimes original txn time is also sent

        $this->generateSignature($params);
        if ($params['signature'] === 'FAIL_UNIONPAY_SIGN_GENERATION') {
            throw new RefundException('UnionPay Refund: Failed to generate request signature (simulated).');
        }

        try {
            // $responseForm = $this->httpClient('POST', $this->getRequestUrl(self::BACK_TRANS_URL_PATH), $params, [], false);
            // $response = []; parse_str($responseForm, $response);
            // Mocked Response for Refund
            $mockResponse = [];
            if ($params['txnAmt'] == '99999997') {
                $mockResponse = ['respCode' => '25', 'respMsg' => 'Original transaction not found or invalid amount', 'orderId' => $params['orderId']];
            } elseif ($params['origQryId'] === 'UP_QID_NO_REFUND'){
                 $mockResponse = ['respCode' => '60', 'respMsg' => 'Transaction cannot be refunded', 'orderId' => $params['orderId']];
            }else {
                $mockResponse = [
                    'respCode' => '00', 'respMsg' => 'Refund Accepted', // Refunds are often async, 00 means accepted by UnionPay
                    'queryId' => 'UP_REFUND_QID_' . uniqid(), // queryId for this refund transaction
                    'orderId' => $params['orderId'],
                    'origQryId' => $params['origQryId'],
                    'txnAmt' => $params['txnAmt']
                ];
            }
            $mockResponse['signature'] = 'VALID_SIGN_FOR_QUERYID_'.($mockResponse['queryId'] ?? 'temprefundqid');
            $response = $mockResponse;
            // End Mock

            if (!isset($response['respCode']) || !in_array($response['respCode'], ['00', 'A6', '03', '04', '05'])) { // 00/A6 for success, 03/04/05 for processing
                throw new RefundException('UnionPay Refund: Failed. ' . ($response['respMsg'] ?? 'Unknown error from gateway refund request.'));
            }
            // Verify signature of refund response
            // if (!$this->verifySignature($response)) { /* ... throw ... */ }

            $refundRespCode = $response['respCode'];
            $finalStatus = 'pending'; // Refunds are typically asynchronous; '00' means accepted for processing.
            if ($refundRespCode === '00' || $refundRespCode === 'A6') {
                // Further check via notification (backUrl) or query for final refund status (e.g. using $response['queryId'])
            } elseif (!in_array($refundRespCode, ['03', '04', '05'])) {
                $finalStatus = 'failed'; // If not success or pending codes, assume failure of submission.
            }

            return [
                'status' => $finalStatus,
                'message' => 'UnionPay Refund Status: ' . ($response['respMsg'] ?? $refundRespCode) . ('. (00 means accepted, final status via notification/query)'),
                'refundId' => $response['queryId'] ?? null, // queryId for the refund transaction itself
                'orderId' => $response['orderId'] ?? null, // The new orderId for this refund operation
                'gatewayReferenceId' => $response['origQryId'] ?? null, // Original transaction's queryId
                'paymentStatus' => 'REFUND_' . $refundRespCode,
                'amount' => $response['txnAmt'] ?? null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new RefundException('UnionPay: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 