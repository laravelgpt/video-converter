<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PeachPaymentsGateway extends PaymentGateway
{
    // Peach Payments API v2 is more common now. URLs depend on product (Checkout, Server-to-Server)
    private const API_BASE_URL_SANDBOX = 'https://testpayments.peachpayments.com/v2'; // Common for Server-to-Server
    private const API_BASE_URL_PRODUCTION = 'https://payments.peachpayments.com/v2';
    private const CHECKOUT_BASE_URL_SANDBOX = 'https://testcheckout.peachpayments.com/checkout'; // For hosted checkout
    private const CHECKOUT_BASE_URL_PRODUCTION = 'https://checkout.peachpayments.com/checkout';

    protected function getDefaultConfig(): array
    {
        return [
            'entityId' => '',        // Your Peach Payments Entity ID (for Server-to-Server API)
            'secretToken' => '',     // Your Peach Payments Secret Token (for Server-to-Server API)
            'checkoutEntityId' => '', // Specific Entity ID for Checkout product if different
            'currency' => 'ZAR',     // Default currency
            'isSandbox' => true,
            'timeout' => 60,
            'paymentType' => 'DB', // Default payment type (DB = Debit, CD = Credit, PA = Preauthorization etc.)
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['entityId'])) {
            throw new InvalidConfigurationException('Peach Payments: entityId is required for Server-to-Server API.');
        }
        if (empty($config['secretToken'])) {
            throw new InvalidConfigurationException('Peach Payments: secretToken is required for Server-to-Server API.');
        }
        // checkoutEntityId would be required if using the Checkout product specifically.
    }

    private function getApiBaseUrl(bool $forCheckout = false): string
    {
        if ($forCheckout) {
            return $this->config['isSandbox'] ? self::CHECKOUT_BASE_URL_SANDBOX : self::CHECKOUT_BASE_URL_PRODUCTION;
        }
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    // Peach Payments Server-to-Server API uses Basic Auth with entityId as username and secretToken as password.
    // Or, for some newer APIs, Bearer token based on these.
    // For Checkout API, it's often a signature for request parameters.
    private function getRequestHeaders(): array
    {
        // This mock assumes a Bearer token style for S2S, which is common for their newer APIs.
        // Older direct POSTs might use form data with `authentication.entityId` and `authentication.token`
        return [
            'Authorization' => 'Bearer ' . $this->config['secretToken'], // Or some form of authentication using entityId too.
            'Content-Type' => 'application/json' // Or application/x-www-form-urlencoded for older APIs
        ];
    }

    // Signature generation for Checkout flow (conceptual)
    private function generateCheckoutSignature(array $params): string
    {
        // Peach Payments signature is typically an HMAC SHA256 of specific fields concatenated in order, using the secret token.
        // The exact fields and order depend on the API version and product.
        // ksort($params); // Often parameters are sorted
        // $stringToSign = implode('|', $params); // Example concatenation
        // return hash_hmac('sha256', $stringToSign, $this->config['secretToken']);
        return 'MOCK_PEACH_SIGNATURE_FOR_' . md5(json_encode($params) . $this->config['secretToken']);
    }

    public function initialize(array $data): array
    {
        // This can either prepare for a Server-to-Server transaction or generate parameters for Checkout (hosted page).
        // This mock will simulate generating parameters for their hosted Checkout page (V2).
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Peach Payments: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            $sanitizedData['currency'] = $this->config['currency'];
        }
        if (empty($sanitizedData['orderId'])) { // merchantTransactionId
            throw new InitializationException('Peach Payments: Missing orderId (merchantTransactionId).');
        }

        $checkoutEntityId = $this->config['checkoutEntityId'] ?? $this->config['entityId'];
        if(empty($checkoutEntityId)){
            throw new InvalidConfigurationException('Peach Payments: checkoutEntityId or entityId is required for Checkout.');
        }

        $params = [
            'authentication.entityId' => $checkoutEntityId,
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'currency' => strtoupper($sanitizedData['currency']),
            'paymentType' => $sanitizedData['paymentType'] ?? $this->config['paymentType'], // e.g. DB
            'merchantTransactionId' => $sanitizedData['orderId'],
            'customer.givenName' => $sanitizedData['firstName'] ?? 'Test',
            'customer.surname' => $sanitizedData['lastName'] ?? 'User',
            'customer.email' => $sanitizedData['email'] ?? 'test@example.com',
            // 'billing.street1' => ..., 'billing.city' => ..., etc.
            // 'shipping. ...'
            // 'shopperResultUrl' => $sanitizedData['returnUrl'] ?? 'https://example.com/peach/return',
            // 'cancelUrl' => $sanitizedData['cancelUrl'] ?? 'https://example.com/peach/cancel',
            // 'notificationUrl' => $sanitizedData['notifyUrl'] ?? 'https://example.com/peach/notify',
            // 'createRegistration' => 'true' // To tokenize card details
        ];

        // Generate signature (conceptual for V2 Checkout JS integration parameters)
        // For a direct redirect to hosted page, signature might be calculated differently or not needed if using a checkout ID.
        // Let's assume for a Server-to-Server API payment:
        // $params['authentication.signature'] = $this->generateCheckoutSignature($params); // This is conceptual
        
        // If using Server-to-Server direct payment API (e.g. /payments endpoint):
        $s2sPayload = [
            'authentication.entityId' => $this->config['entityId'],
            // 'authentication.token' => $this->config['secretToken'], // Or Bearer header depending on specific API
            'amount' => $params['amount'],
            'currency' => $params['currency'],
            'paymentType' => $params['paymentType'],
            'merchantTransactionId' => $params['merchantTransactionId'],
            // Add card details, bank details, or other payment instrument details here for S2S
            // e.g. 'card.number' => ..., 'card.expiryMonth' => ..., etc.
            // This mock will not handle raw card data directly but assume a token/registrationId if it were S2S.
        ];
        // If a payment method token (registrationId) is provided:
        if (!empty($sanitizedData['paymentToken'])) {
            $s2sPayload['registrationId'] = $sanitizedData['paymentToken'];
        }

        // For this mock, we'll simulate the newer Checkout API which returns a `checkoutId` to be used with their JS library.
        // The /checkouts endpoint. POST with entityId in body, amount, currency, merchantTransactionId.
        $checkoutInitPayload = [
            'authentication.entityId' => $checkoutEntityId,
            'amount' => $params['amount'],
            'currency' => $params['currency'],
            'merchantTransactionId' => $params['merchantTransactionId'],
            'paymentType' => $params['paymentType'],
             // 'shopperResultUrl' => $params['shopperResultUrl'], // Important for redirect after completion
        ];

        try {
            // $url = $this->getApiBaseUrl() . '/checkouts'; // Or a different URL if not using Checkout product for init
            // For /checkouts, auth is often Bearer token with Secret Token for some newer APIs, or entityId in payload
            // $checkoutHeaders = ['Authorization' => 'Bearer ' . $this->config['secretToken'], 'Content-Type' => 'application/json'];
            // $response = $this->httpClient('POST', $url, $checkoutInitPayload, $checkoutHeaders);
            // Mocked Response for /checkouts
            if ($checkoutInitPayload['amount'] == '9999.00') {
                 throw new InitializationException('Peach Payments: Checkout creation failed (simulated error amount).');
            }
            $mockCheckoutId = 'PEACH_CHECKOUTID_' . strtoupper(uniqid());
            $mockResponseBody = [
                'id' => $mockCheckoutId,
                'result' => ['code' => '000.200.100', 'description' => 'Successfully created checkout' ],
                'timestamp' => date('Y-m-d H:i:s') . ' UTC',
                // 'redirect' => [...] // May contain redirect info for some payment methods
            ];
            $response = ['body' => $mockResponseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                throw new InitializationException('Peach Payments: Failed to initialize checkout. Error: ' . ($response['body']['result']['description'] ?? 'Unknown API error'));
            }

            // The checkoutId is used with Peach's JS library to render the payment form.
            // A redirect URL is not directly provided by this /checkouts response.
            // The JS library handles the redirect or embedded form.
            $checkoutScriptUrl = ($this->config['isSandbox'] ? 'https://testcheckout.peachpayments.com/checkout.js' : 'https://checkout.peachpayments.com/checkout.js');

            return [
                'status' => 'pending_client_action', // Client needs to use JS with checkoutId
                'message' => 'Peach Payments checkout created. Use checkoutId with Peach Payments JS library.',
                'checkoutId' => $response['body']['id'],
                'checkoutScriptUrl' => $checkoutScriptUrl, // URL for the JS library
                'orderId' => $params['merchantTransactionId'],
                'gatewayReferenceId' => $response['body']['id'], // This is the checkout/payment ID
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Peach Payments: Checkout initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This would typically handle a webhook/notification from Peach Payments.
        // The payload structure varies. For Checkout, you often get the resourcePath in notificationUrl query.
        // Then you fetch the status using that resourcePath.
        $sanitizedData = $this->sanitize($data); // This is the webhook payload or query params.

        // Example: If `id` and `resourcePath` are sent as query parameters to notificationUrl
        $resourcePath = $sanitizedData['resourcePath'] ?? null;
        $checkoutId = $sanitizedData['id'] ?? null; // Might be the same as checkoutId from init

        if (empty($resourcePath) && empty($checkoutId)) {
            // Or if the webhook directly contains the full transaction data:
            if(empty($sanitizedData['result']['code']) || empty($sanitizedData['merchantTransactionId'])){
                throw new ProcessingException('Peach Payments Webhook: Invalid payload. Missing resourcePath/id or direct transaction data.');
            }
        }
        
        // Scenario 1: Webhook gives full data (less common for new APIs, but possible)
        if(isset($sanitizedData['result']['code'])){
            $resultCode = $sanitizedData['result']['code'] ?? '';
            $resultDesc = $sanitizedData['result']['description'] ?? 'No description';
            $merchantTransactionId = $sanitizedData['merchantTransactionId'] ?? null;
            $peachPaymentId = $sanitizedData['id'] ?? $checkoutId; // Peach Payment ID

            $finalStatus = 'failed';
            // Peach Payments result codes: https://support.peachpayments.com/support/solutions/articles/47000077295-result-codes
            // Success usually starts with 000.000 or 000.100
            if (preg_match('/^(000\.000|000\.100|000\.200)/i', $resultCode) || preg_match('/^(000\.600)/i', $resultCode) /* successful risk bank */ ) {
                $finalStatus = 'success';
            } elseif (preg_match('/^(000\.400\.0|000\.400\.1|000\.400\.2)/i', $resultCode) || preg_match('/^(800\.400\.1|800\.400\.2)/i', $resultCode)) { // Pending codes
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'Peach Payments direct webhook: ' . $resultDesc . ' (Code: ' . $resultCode . ')',
                'transactionId' => $peachPaymentId,
                'orderId' => $merchantTransactionId,
                'paymentStatus' => $resultCode,
                'amount' => $sanitizedData['amount'] ?? null,
                'currency' => $sanitizedData['currency'] ?? null,
                'rawData' => $sanitizedData
            ];
        }

        // Scenario 2: Webhook provides resourcePath, fetch status (More common for Checkout)
        if (empty($resourcePath)) {
             // If checkoutId is available, construct a possible resourcePath
             if ($checkoutId) $resourcePath = '/v2/checkouts/' . $checkoutId . '/payment'; // Common pattern
             else throw new ProcessingException('Peach Payments Webhook: Missing resourcePath to fetch transaction status.');
        }
        
        return $this->fetchTransactionStatus($resourcePath, $checkoutId, ($sanitizedData['merchantTransactionIdForWebhookVerify'] ?? null));
    }

    private function fetchTransactionStatus(string $resourcePath, ?string $checkoutId = null, ?string $merchantTxId = null)
    {
        try {
            // $url = ($this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION) . $resourcePath;
            // For /checkouts/{id}/payment, auth is Bearer secretToken
            // $headers = ['Authorization' => 'Bearer ' . $this->config['secretToken']]; 
            // $response = $this->httpClient('GET', $url, [], $headers);
            // Mocked Response for fetching status via resourcePath
            if ($resourcePath === '/v2/checkouts/FAIL_PATH/payment') {
                 throw new ProcessingException('Peach Payments: Failed to fetch transaction status via resourcePath (simulated API error).');
            }
            $mockResultCode = '800.100.100'; // Default to a failed code
            $mockResultDesc = 'Transaction declined by bank';
            $mockStatus = 'failed';
            $mockAmount = '100.00';
            $mockCurrency = 'ZAR';
            $mockPeachId = $checkoutId ?? 'PEACH_UNKNOWNID';
            $mockMerchantTxId = $merchantTxId ?? ('ORD_' . uniqid());

            if (strpos($resourcePath, 'SUCCESS_CHECKOUT') !== false || $checkoutId === 'PEACH_CHECKOUTID_SUCCESS') {
                $mockResultCode = '000.000.000'; $mockResultDesc = 'Transaction Success'; $mockStatus = 'success';
            } elseif (strpos($resourcePath, 'PENDING_CHECKOUT') !== false || $checkoutId === 'PEACH_CHECKOUTID_PENDING') {
                $mockResultCode = '000.400.100'; $mockResultDesc = 'Transaction Pending'; $mockStatus = 'pending';
            }

            $responseBody = [
                'id' => $mockPeachId, // This is Peach's payment ID
                'merchantTransactionId' => $mockMerchantTxId,
                'amount' => $mockAmount,
                'currency' => $mockCurrency,
                'paymentType' => 'DB',
                'result' => ['code' => $mockResultCode, 'description' => $mockResultDesc],
                'resultDetails' => ['AcquirerResponse' => '00'],
                'timestamp' => date('Y-m-d H:i:s') . ' UTC'
                // ... other details like card, customer, etc.
            ];
            $response = ['body' => $responseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                throw new ProcessingException('Peach Payments: Failed to fetch transaction status from resourcePath. Error: ' . ($response['body']['result']['description'] ?? 'Unknown API error'));
            }
            $txData = $response['body'];
            $resultCode = $txData['result']['code'] ?? '';
            $resultDesc = $txData['result']['description'] ?? 'No description';
            $finalStatus = $mockStatus; // Use pre-determined mock status for simplicity here

            return [
                'status' => $finalStatus,
                'message' => 'Peach Payments status via resourcePath: ' . $resultDesc . ' (Code: ' . $resultCode . ')',
                'transactionId' => $txData['id'],
                'orderId' => $txData['merchantTransactionId'],
                'paymentStatus' => $resultCode,
                'amount' => $txData['amount'] ?? null,
                'currency' => $txData['currency'] ?? null,
                'rawData' => $txData
            ];
        } catch (\Exception $e) {
            throw new ProcessingException('Peach Payments: Status fetch failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        // Verification can be done by transaction ID (Peach Payment ID) or merchantTransactionId.
        // This usually hits an endpoint like /v2/payments/{id} or /v2/query
        $sanitizedData = $this->sanitize($data);
        $peachPaymentId = $sanitizedData['transactionId'] ?? null; // Peach's ID
        $merchantTransactionId = $sanitizedData['orderId'] ?? null; // Your ID

        if (empty($peachPaymentId) && empty($merchantTransactionId)) {
            throw new VerificationException('Peach Payments: Either transactionId (Peach ID) or orderId (merchantTransactionId) is required for verification.');
        }
        
        // Peach provides a Query API: POST to /v2/query with authentication.entityId and merchantTransactionId
        // Or GET /v2/payments/{id} if you have Peach Payment ID
        // This mock will simulate GET /v2/payments/{id} if peachPaymentId is available.
        // Otherwise, it will simulate POST /v2/query if merchantTransactionId is available.

        $resourcePath = '';
        if($peachPaymentId){
            $resourcePath = '/payments/' . $peachPaymentId;
        } elseif($merchantTransactionId){
            // This is conceptual. Real query might be POST with merchantTransactionId in body
            // For this mock, we'll just use the fetchTransactionStatus with a constructed path
            // Or assume verify can use the same logic as processing a webhook with resourcePath by knowing the merchantTxId.
            // Let's simplify and say verify relies on having Peach Payment ID for this mock.
            throw new VerificationException('Peach Payments: Verification mock requires transactionId (Peach Payment ID). Query by merchantTransactionId is more complex.');
        }

        // Re-use the fetch logic as it gets the full status object
        return $this->fetchTransactionStatus($resourcePath, $peachPaymentId, $merchantTransactionId);
    }

    public function refund(array $data): array
    {
        // Refunds require the original Peach Payment ID (transactionId).
        // POST to /v2/payments/{id}/refund or similar endpoint.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Peach Payment ID of original transaction
            throw new RefundException('Peach Payments: transactionId (Peach Payment ID) is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Peach Payments: Invalid or missing amount for refund.');
        }
        if (empty($sanitizedData['currency'])) {
            $sanitizedData['currency'] = $this->config['currency'];
        }

        $payload = [
            'authentication.entityId' => $this->config['entityId'],
            // 'authentication.token' => $this->config['secretToken'], // Or Bearer header
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'currency' => strtoupper($sanitizedData['currency']),
            'paymentType' => 'RF', // RF for Refund. Or CD for Credit if it's a standalone credit.
            // 'merchantTransactionId' => $sanitizedData['refundId'] ?? 'REF_'.uniqid(), // Optional: new reference for refund
        ];

        try {
            // $url = $this->getApiBaseUrl() . '/payments/' . $sanitizedData['transactionId'] . '/refund';
            // $headers = $this->getRequestHeaders(); // Bearer token with Secret Token
            // $response = $this->httpClient('POST', $url, $payload, $headers);
            // Mocked Response
            if ($payload['amount'] == '99.99') {
                 throw new RefundException('Peach Payments: API rejected refund (simulated amount error).');
            }
            $mockRefundId = 'PEACH_REFUNDID_' . strtoupper(uniqid());
            $mockResponseBody = [
                'id' => $mockRefundId, // ID of the refund transaction
                'referencedId' => $sanitizedData['transactionId'], // ID of original payment
                'paymentType' => 'RF',
                'amount' => $payload['amount'],
                'currency' => $payload['currency'],
                'result' => ['code' => '000.000.000', 'description' => 'Refund successfully processed' ],
                'timestamp' => date('Y-m-d H:i:s') . ' UTC'
            ];
             if ($sanitizedData['transactionId'] === 'PEACHID_NO_REFUND') {
                $mockResponseBody['result'] = ['code' => '700.400.200', 'description' => 'Referenced session is not chargeable/refundable.'];
            }
            $response = ['body' => $mockResponseBody, 'status_code' => ($mockResponseBody['result']['code'] === '700.400.200' ? 400 : 200)];

            if ($response['status_code'] !== 200 || !preg_match('/^(000\.000|000\.100)/i', $response['body']['result']['code'] ?? '')) {
                throw new RefundException('Peach Payments: Refund API call failed. Error: ' . ($response['body']['result']['description'] ?? 'Unknown API error'));
            }

            // Refunds can be asynchronous, final status via webhook or query.
            return [
                'status' => 'success', // Or pending if API indicates async processing
                'message' => 'Peach Payments refund processed. ' . $response['body']['result']['description'],
                'refundId' => $response['body']['id'], // ID of the refund transaction itself
                'gatewayReferenceId' => $response['body']['referencedId'], // Original Peach Payment ID
                'paymentStatus' => $response['body']['result']['code'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Peach Payments: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 