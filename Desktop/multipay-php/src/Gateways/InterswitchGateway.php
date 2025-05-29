<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class InterswitchGateway extends PaymentGateway
{
    // Interswitch WebPAY/Quickteller URLs. These can vary based on product & region.
    // WebPAY Redirect URL (example)
    private const WEBPAY_REDIRECT_URL_SANDBOX = 'https://sandbox.interswitchng.com/webpay/pay';
    private const WEBPAY_REDIRECT_URL_PRODUCTION = 'https://webpay.interswitchng.com/pay'; // Or specific bank-hosted URL
    // Quickteller API URL for transaction query (example)
    private const QUICKTELLER_API_URL_SANDBOX = 'https://qa.interswitchng.com/quicktellerplatform/api/v2/querytransaction';
    private const QUICKTELLER_API_URL_PRODUCTION = 'https://quickteller.interswitchng.com/quicktellerplatform/api/v2/querytransaction';
    // For Interswitch APIs, passport.interswitchng.com is often used for auth token generation
    private const PASSPORT_URL_SANDBOX = 'https://sandbox.interswitchng.com/passport/oauth/token';
    private const PASSPORT_URL_PRODUCTION = 'https://passport.interswitchng.com/passport/oauth/token';

    protected function getDefaultConfig(): array
    {
        return [
            'productId' => '',       // Your Interswitch Product ID
            'merchantId' => '',      // Your Interswitch Merchant ID (sometimes same as PayItemID or TerminalID)
            'apiKey' => '',          // Your Interswitch API Key (for hashing/MAC generation or Bearer token)
            'macKey' => '',          // MAC Key if using that hashing method (older WebPAY)
            'terminalId' => '',      // Terminal ID, often used with Quickteller APIs
            'clientId' => '',        // Client ID for OAuth token generation (newer APIs)
            'clientSecret' => '',    // Client Secret for OAuth token generation
            'isSandbox' => true,
            'timeout' => 60,
            'defaultCurrencyCode' => '566', // NGN for Nigeria. Interswitch uses numeric currency codes.
            'defaultReturnUrl' => 'https://example.com/interswitch/return',
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['productId'])) {
            throw new InvalidConfigurationException('Interswitch: productId is required.');
        }
        // Depending on specific Interswitch product (WebPAY, Quickteller API, etc.), different keys are primary.
        // For WebPAY classic, merchantId and macKey might be key.
        // For newer APIs (e.g., Quickteller direct API), terminalId, apiKey (as Bearer) or clientId/clientSecret for OAuth might be needed.
        // This mock will try to be flexible but highlight potential needs.
        if (empty($config['merchantId']) && empty($config['terminalId'])){
            throw new InvalidConfigurationException('Interswitch: merchantId or terminalId is required.');
        }
        if (empty($config['apiKey']) && empty($config['macKey']) && (empty($config['clientId']) || empty($config['clientSecret']))){
            throw new InvalidConfigurationException('Interswitch: apiKey, macKey, or clientId/clientSecret pair is required.');
        }
    }

    private function getWebpayRedirectUrl(): string
    {
        return $this->config['isSandbox'] ? self::WEBPAY_REDIRECT_URL_SANDBOX : self::WEBPAY_REDIRECT_URL_PRODUCTION;
    }

    private function getQuicktellerApiUrl(): string
    {
        return $this->config['isSandbox'] ? self::QUICKTELLER_API_URL_SANDBOX : self::QUICKTELLER_API_URL_PRODUCTION;
    }
    
    private function getPassportUrl(): string
    {
        return $this->config['isSandbox'] ? self::PASSPORT_URL_SANDBOX : self::PASSPORT_URL_PRODUCTION;
    }

    // Hash generation for WebPAY redirect (SHA512 or SHA256, depends on integration)
    // Typically: txn_ref + product_id + pay_item_id + amount + site_redirect_url + MacKey
    private function generateWebpayHash(array $params): string
    {
        $stringToHash = ($params['txn_ref'] ?? '') .
                      ($params['product_id'] ?? '') .
                      ($params['pay_item_id'] ?? '') . // Often same as merchantId or a specific item ID
                      ($params['amount'] ?? '') .
                      ($params['site_redirect_url'] ?? '') .
                      ($this->config['macKey'] ?? '');
        return hash('sha512', $stringToHash); // Common, but could be SHA256. Check specific docs.
    }

    // Get Access Token for newer APIs (conceptual)
    private function getAccessToken(): string {
        if (empty($this->config['clientId']) || empty($this->config['clientSecret'])) {
            // Fallback to apiKey if OAuth creds not set, assuming apiKey can be used as Bearer token directly for some APIs
            if (!empty($this->config['apiKey'])) return $this->config['apiKey'];
            throw new InvalidConfigurationException('Interswitch: clientId and clientSecret are required for OAuth token, or apiKey for direct Bearer auth.');
        }
        // $auth = base64_encode($this->config['clientId'] . ':' . $this->config['clientSecret']);
        // $payload = ['grant_type' => 'client_credentials', 'scope' => 'profile']; // Scope can vary
        // $headers = ['Authorization' => 'Basic ' . $auth, 'Content-Type' => 'application/x-www-form-urlencoded'];
        // $response = $this->httpClient('POST', $this->getPassportUrl(), $payload, $headers, false); // false for form data
        // Mocked Response for token
        if($this->config['clientId'] === 'FAIL_ISW_TOKEN') throw new \Exception('Failed to get ISW access token.');
        return 'MOCK_ISW_ACCESS_TOKEN_'.uniqid();
    }

    public function initialize(array $data): array
    {
        // This mock simulates the WebPAY redirect flow.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Interswitch: Invalid amount. Amount in Kobo/lowest unit.');
        }
        if (empty($sanitizedData['orderId'])) { // txn_ref
            throw new InitializationException('Interswitch: Missing orderId (txn_ref).');
        }

        $amountInKobo = (int)round($sanitizedData['amount']); // Interswitch expects amount in kobo/cents

        $payload = [
            'product_id' => $this->config['productId'],
            'pay_item_id' => $this->config['merchantId'], // Often, pay_item_id is same as merchantId or a specific item code
            'amount' => (string)$amountInKobo, // String representation of amount in kobo
            'currency' => $this->config['defaultCurrencyCode'], // Numeric currency code, e.g., 566 for NGN
            'site_redirect_url' => $sanitizedData['returnUrl'] ?? $this->config['defaultReturnUrl'],
            'txn_ref' => $sanitizedData['orderId'],
            'cust_id' => $sanitizedData['customerId'] ?? ('CUST_' . $sanitizedData['orderId']), // Optional
            'cust_name' => $sanitizedData['customerName'] ?? 'Valued Customer', // Optional
            // 'site_name' => $this->config['siteName'] ?? 'YourWebsite.com',
            // 'cust_email' => $sanitizedData['email'] ?? '',
            // 'hash' will be generated and added
        ];

        if (empty($this->config['macKey'])) {
            throw new InvalidConfigurationException('Interswitch WebPAY: macKey is required for hash generation in this flow.');
        }
        $payload['hash'] = $this->generateWebpayHash($payload);

        // Simulate an error condition for testing
        if ($payload['amount'] === '9999999') {
            throw new InitializationException('Interswitch: Simulated error during hash generation or param validation.');
        }

        $paymentUrl = $this->getWebpayRedirectUrl();
        // User will be redirected to this URL with parameters typically as GET query string or POST form.
        // For WebPAY, it's usually a POST form from merchant site to Interswitch.

        return [
            'status' => 'pending_user_action',
            'message' => 'Interswitch WebPAY initialized. Prepare form to POST data to Interswitch.',
            'paymentUrl' => $paymentUrl, // URL to POST the form to
            'formData' => $payload,    // Data for hidden fields in the form
            'orderId' => $sanitizedData['orderId'],
            'gatewayReferenceId' => $sanitizedData['orderId'], // txn_ref is used until Interswitch payment ref is known
            'rawData' => ['formAction' => $paymentUrl, 'formFields' => $payload]
        ];
    }

    public function process(array $data): array
    {
        // This processes the redirect back from Interswitch WebPAY or a webhook notification.
        // $data would contain parameters like `txnref`, `payRef`, `retRef`, `apprAmt`, `resp` (response code).
        $sanitizedData = $this->sanitize($data); // Parameters from redirect/webhook

        $txnRef = $sanitizedData['txnref'] ?? null; // Your original transaction reference
        $paymentRef = $sanitizedData['payRef'] ?? null; // Interswitch's payment reference (important!)
        $retrievalRef = $sanitizedData['retRef'] ?? null; // Retrieval Reference Number
        $responseCode = $sanitizedData['resp'] ?? null; // e.g., '00' for success
        $amountPaid = $sanitizedData['apprAmt'] ?? null; // Approved amount in KOBO/cents

        if (empty($txnRef) || empty($responseCode)) {
            throw new ProcessingException('Interswitch: Invalid callback/webhook data. Missing txnref or response code.');
        }

        // Verify hash if this were a webhook with a signature (Interswitch uses various methods)
        // For redirect, often the parameters are plain, and server-to-server query is needed for confirmation.

        $finalStatus = 'failed';
        $message = 'Interswitch payment processed. Response Code: ' . $responseCode;

        if ($responseCode === '00') {
            $finalStatus = 'success';
            $message .= ' Transaction successful.';
            if (empty($paymentRef)) {
                 $message .= ' Interswitch Payment Reference (payRef) is missing, which is unusual for success.';
            }
        } elseif (in_array($responseCode, ['Z0', 'Z1', 'Z2', 'Z3', 'Z4', 'Z5', 'Z6'])) { // Example pending/deferred codes
            $finalStatus = 'pending';
            $message .= ' Transaction is pending or deferred.';
        } else {
            $message .= ' Transaction failed or was declined.';
        }
        
        if (($sanitizedData['custom_force_fail'] ?? null) === 'true') {$finalStatus = 'failed'; $message = 'Forced failure.';}

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $paymentRef ?? $retrievalRef, // Interswitch paymentRef or retRef is the key ID
            'orderId' => $txnRef,
            'paymentStatus' => $responseCode,
            'amount' => isset($amountPaid) ? ($amountPaid / 100) : null, // Amount is in kobo
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Verify transaction status using Quickteller API (or specific WebPAY query if available).
        // Requires ProductID/TerminalID, your transaction reference, and often an auth token.
        $sanitizedData = $this->sanitize($data);
        $orderId = $sanitizedData['orderId'] ?? null; // Your txn_ref
        $iswPaymentRef = $sanitizedData['transactionId'] ?? null; // Interswitch's payment reference, if known

        if (empty($orderId)) {
            throw new VerificationException('Interswitch: orderId (original txn_ref) is required for verification.');
        }

        try {
            // $accessToken = $this->getAccessToken(); // For APIs requiring OAuth
            // For Quickteller query, headers often include TerminalId, Authorization (Bearer token or custom hash), Timestamp, Nonce etc.
            // The exact request structure for query (GET params vs JSON body, headers) varies.
            // This mock simulates a GET request to Quickteller query API with TerminalID and custom hash/signature if apiKey is used directly.
            
            // For query, often GET with ?merchantReference={orderId}&terminalId={terminalId} etc.
            // Or POST with JSON body for other API versions.
            // Let's assume a GET query with custom signature in headers. Interswitch has many ways...
            
            $terminalId = $this->config['terminalId'] ?? $this->config['merchantId'];
            if(empty($terminalId)) throw new InvalidConfigurationException('Interswitch: terminalId or merchantId (as terminalId) needed for query.');

            // This is a conceptual hash/signature for query API headers. Real one will be more complex.
            // $timestamp = time(); $nonce = uniqid();
            // $stringToSign = $this->getQuicktellerApiUrl() . '&requestReference=' . $orderId . '&terminalId=' . $terminalId . '&' . $timestamp . '&' . $nonce;
            // $signature = hash_hmac('sha256', $stringToSign, $this->config['apiKey']); // Or clientSecret for OAuth context
            // $headers = ['Authorization' => 'InterswitchAuth ' . base64_encode($this->config['clientId'] ?? $this->config['apiKey']), 'Signature' => $signature, ...];

            // Mocked GET Response from Quickteller API
            $mockTransaction = null;
            if ($orderId === 'TXNREF_SUCCESS_ISW' || $iswPaymentRef === 'PAYREF_SUCCESS_ISW') {
                $mockTransaction = [
                    'paymentReference' => $iswPaymentRef ?? 'PAYREF_MOCK_S_'.uniqid(),
                    'transactionDate' => date(DATE_ISO8601),
                    'amount' => ($sanitizedData['originalAmountKoboForTest'] ?? 500000), // Amount in kobo
                    'responseCode' => '00',
                    'responseDescription' => 'Approved Or Completed Successfully',
                    'merchantReference' => $orderId,
                    'retrievalReferenceNumber' => 'RETR_MOCK_S_'.uniqid(),
                    // ... other fields like cardScheme, maskedPan, etc.
                ];
            } elseif ($orderId === 'TXNREF_PENDING_ISW') {
                 $mockTransaction = ['merchantReference' => $orderId, 'responseCode' => 'Z0', 'responseDescription' => 'Transaction in progress', 'amount' => 200000];
            } else { // Not found or failed
                 $mockTransaction = ['merchantReference' => $orderId, 'responseCode' => '06', 'responseDescription' => 'Transaction Not Found/Failed', 'amount' => 0];
            }
            $response = ['body' => $mockTransaction, 'status_code' => 200]; // Assume API itself returns 200

            if ($response['status_code'] !== 200 || empty($response['body']['responseCode'])) {
                throw new VerificationException('Interswitch: Query API call failed or invalid response.');
            }

            $txData = $response['body'];
            $respCode = $txData['responseCode'];
            $finalStatus = 'failed';
            if ($respCode === '00' || $respCode === '90000' /* Common success for Quickteller */) {
                $finalStatus = 'success';
            } elseif (in_array($respCode, ['Z0', 'Z1', 'Z6', '9000D' /*Deferred*/])) { // Example pending codes
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'Interswitch (simulated query) status: ' . ($txData['responseDescription'] ?? 'N/A') . ' (Code: ' . $respCode . ')',
                'transactionId' => $txData['paymentReference'] ?? $txData['retrievalReferenceNumber'] ?? null,
                'orderId' => $txData['merchantReference'],
                'paymentStatus' => $respCode,
                'amount' => isset($txData['amount']) ? ($txData['amount'] / 100) : null, // Amount in kobo
                'rawData' => $txData
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Interswitch: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Interswitch refunds can be complex and depend on the specific product (WebPAY, Quickteller, etc.)
        // Some might require using a Bill Payment API for payouts, or a specific Refund API if available.
        // This mock will be highly conceptual.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Original Interswitch Payment Reference or RetrievalReferenceNumber
            throw new RefundException('Interswitch: transactionId (Interswitch Payment/Retrieval Ref) is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Interswitch: Invalid or missing amount for refund (in Kobo/cents).');
        }

        // Conceptual payload for a refund API
        $payload = [
            'paymentReference' => $sanitizedData['transactionId'],
            'amount' => (int)round($sanitizedData['amount']), // Amount in Kobo
            'terminalId' => $this->config['terminalId'] ?? $this->config['merchantId'],
            'refundReason' => $sanitizedData['reason'] ?? 'Merchant initiated refund',
            'transactionReference' => $sanitizedData['refundOrderId'] ?? ('REF_' . $sanitizedData['orderIdForRefund'] ?? uniqid()), // Your ref for the refund
        ];
        // Headers would likely require Authorization (Bearer token or custom signature scheme)

        try {
            // $accessToken = $this->getAccessToken();
            // $headers = ['Authorization' => 'Bearer ' . $accessToken, 'Content-Type' => 'application/json', ...];
            // $url = ... // Specific refund API endpoint
            // $response = $this->httpClient('POST', $url, $payload, $headers);
            // Mocked Response
            if ($payload['amount'] == 99999) {
                 throw new RefundException('Interswitch: API rejected refund (simulated amount error).');
            }
            $mockResponseBody = [];
            if ($sanitizedData['transactionId'] === 'NO_REFUND_ISW'){
                $mockResponseBody = ['responseCode' => '51', 'responseMessage' => 'Refund not permitted or transaction not found'];
            } else {
                 $mockResponseBody = [
                    'responseCode' => '00', // Or '90000' for success
                    'responseMessage' => 'Refund request processed successfully',
                    'refundReference' => 'ISW_REFUNDID_' . strtoupper(uniqid()),
                    'originalPaymentReference' => $sanitizedData['transactionId']
                ];
            }
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || !in_array(($response['body']['responseCode'] ?? '99'), ['00', '90000'])) {
                throw new RefundException('Interswitch: Refund API call failed. Error: ' . ($response['body']['responseMessage'] ?? 'Unknown API error'));
            }

            return [
                'status' => 'success', // Or pending if async
                'message' => 'Interswitch refund request processed. ' . $response['body']['responseMessage'],
                'refundId' => $response['body']['refundReference'] ?? null,
                'gatewayReferenceId' => $response['body']['originalPaymentReference'] ?? $sanitizedData['transactionId'],
                'paymentStatus' => 'REFUNDED', // Or specific status from response
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Interswitch: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 