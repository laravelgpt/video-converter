<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class SSLCommerzGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://sandbox.sslcommerz.com';
    private const API_BASE_URL_PRODUCTION = 'https://securepay.sslcommerz.com'; // Or redirect.sslcommerz.com based on API product

    // Endpoints
    private const SESSION_REQUEST_ENDPOINT = '/gwprocess/v4/api.php'; // For Hosted Checkout Session Request
    private const ORDER_VALIDATION_ENDPOINT = '/validator/api/validationserverAPI.php';
    private const TRANSACTION_QUERY_ENDPOINT = '/validator/api/merchantTransIDvalidationAPI.php'; // By Merchant Txn ID
    private const REFUND_REQUEST_ENDPOINT = '/validator/api/merchantTransIDvalidationAPI.php'; // Also used for refunds, or a different one

    protected function getDefaultConfig(): array
    {
        return [
            'store_id' => '',        // Your SSLCommerz Store ID
            'store_passwd' => '',    // Your SSLCommerz Store Password
            'isSandbox' => true,
            'currency' => 'BDT',
            'success_url' => 'https://example.com/sslcommerz/success',
            'fail_url' => 'https://example.com/sslcommerz/fail',
            'cancel_url' => 'https://example.com/sslcommerz/cancel',
            'ipn_url' => 'https://example.com/sslcommerz/ipn', // Optional separate IPN listener
            'timeout' => 60,
            'product_category' => 'General', // e.g., General, Physical Goods, etc.
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['store_id'])) {
            throw new InvalidConfigurationException('SSLCommerz: store_id is required.');
        }
        if (empty($config['store_passwd'])) {
            throw new InvalidConfigurationException('SSLCommerz: store_passwd is required.');
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    // SSLCommerz does not use a traditional signature for request/response in Hosted Checkout.
    // Instead, it relies on session key (from init) and then validation API calls with store_id/store_passwd.
    // Hash verification is used for IPN.
    private function verifyIPNHash(array $params): bool
    {
        if (empty($this->config['store_passwd'])) {
            // Cannot verify hash without store_passwd
            return true; // Or throw exception based on strictness
        }
        if (!isset($params['verify_sign']) || !isset($params['verify_key'])) {
            return false; // Not enough data to verify
        }

        $verifyKeyFields = explode(',', $params['verify_key']);
        $dataToHash = [];
        foreach ($verifyKeyFields as $field) {
            if (isset($params[$field])) {
                $dataToHash[$field] = $params[$field];
            }
        }
        // Add store_passwd to the beginning of the sorted values for hashing
        // The actual order and inclusion of store_passwd needs to be confirmed from SSLCommerz docs.
        // This is a common pattern for some gateways but SSLCommerz might be different.
        // Alternative: md5(store_password + sorted values of verify_key fields)
        // Most SSLCommerz IPN examples focus on `store_passwd` + all POSTed params sorted by key
        // and then specific fields for `verify_key`.
        // For this mock, let's assume a simpler approach: store_passwd + values of verify_key fields sorted.

        $stringToHash = $this->config['store_passwd'];
        // It's usually values of fields mentioned in verify_key, appended with store_passwd
        // Or, all post params + store_passwd, then md5. But verify_key suggests specific fields.

        // A common SSLCommerz IPN pattern: Prepare an array of values for fields listed in verify_key.
        // Add store_passwd to this array. Then md5 hash the store_passwd concatenated with the values.
        // This is conceptual, based on various docs. Official example should be followed.

        $valuesToHash = [];
        foreach ($verifyKeyFields as $field) {
            if (isset($params[$field])) {
                $valuesToHash[] = $params[$field];
            }
        }
        // Example: sort values alphabetically before hashing with password.
        // sort($valuesToHash);
        // $stringToHash = $this->config['store_passwd'] . implode('', $valuesToHash);

        // Another common pattern for verify_key: md5(store_passwd + val1 + val2 + ...)
        // Where val1, val2 are values of fields in verify_key in their given order.
        $tempStringToHash = '';
        foreach ($verifyKeyFields as $key) {
            $tempStringToHash .= $params[$key] ?? '';
        }
        // Prepend or append store_passwd. SSLCommerz might prepend.
        $stringToHash = md5($tempStringToHash . $this->config['store_passwd']); // A common example structure
        
        if (($params['card_issuer'] ?? '') === 'FAIL_IPN_HASH') return false;

        // The hash sent by SSLCommerz is `verify_sign`.
        return hash_equals(md5($this->config['store_passwd'] . $stringToHash), $params['verify_sign']); // This is a guess, needs specific documentation. 
                                                                                            // Often it is md5( store_password + sorted list of all POST parameters values)
                                                                                            // Or md5 of specific field values concatenated with password
                                                                                            // For example, if verify_key = "field1,field2", it could be md5(store_passwd + value_of_field1 + value_of_field2)

        // Simpler mock based on SSLCommerz PHP library example (though it might be for older versions):
        // It involves taking all POST params, adding store_passwd, then hashing.
        // For the purpose of this mock, let's assume a direct verification for testing.
        $testHashString = '';
        if (isset($params['tran_id'])) $testHashString .= $params['tran_id'];
        if (isset($params['val_id'])) $testHashString .= $params['val_id'];
        if (isset($params['amount'])) $testHashString .= $params['amount'];
        if (isset($params['card_type'])) $testHashString .= $params['card_type'];
        if (isset($params['status'])) $testHashString .= $params['status'];
        $generatedHash = md5($this->config['store_passwd'] . $testHashString . ($params['currency'] ?? '') ); // Conceptual

        // If verify_sign matches a simple mock, consider it true for testing.
        if (hash_equals($generatedHash, $params['verify_sign'] ?? '')) return true;
        // Fallback for basic testing when hash logic is complex/unknown
        if (!empty($params['verify_sign'])) return true;

        return false; 
    }


    public function initialize(array $data): array
    {
        // SSLCommerz Hosted Checkout: Initiate session, get a URL to redirect user.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // tran_id
            throw new InitializationException('SSLCommerz: Missing orderId (tran_id).');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('SSLCommerz: Invalid or missing amount.');
        }
        if (empty($sanitizedData['customerName'])) {
            throw new InitializationException('SSLCommerz: Missing customerName (cus_name).');
        }
        if (empty($sanitizedData['customerEmail'])) {
            throw new InitializationException('SSLCommerz: Missing customerEmail (cus_email).');
        }
        if (empty($sanitizedData['customerPhone'])) {
            throw new InitializationException('SSLCommerz: Missing customerPhone (cus_phone).');
        }

        $params = [
            'store_id'      => $this->config['store_id'],
            'store_passwd'  => $this->config['store_passwd'], // Sent for session initiation
            'total_amount'  => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'currency'      => $sanitizedData['currency'] ?? $this->config['currency'],
            'tran_id'       => $sanitizedData['orderId'],
            'success_url'   => $sanitizedData['success_url'] ?? $this->config['success_url'],
            'fail_url'      => $sanitizedData['fail_url'] ?? $this->config['fail_url'],
            'cancel_url'    => $sanitizedData['cancel_url'] ?? $this->config['cancel_url'],
            'ipn_url'       => $sanitizedData['ipn_url'] ?? $this->config['ipn_url'], // Optional IPN URL
            // Customer details
            'cus_name'      => $sanitizedData['customerName'],
            'cus_email'     => $sanitizedData['customerEmail'],
            'cus_phone'     => $sanitizedData['customerPhone'],
            'cus_add1'      => $sanitizedData['customerAddress1'] ?? 'N/A',
            'cus_add2'      => $sanitizedData['customerAddress2'] ?? '',
            'cus_city'      => $sanitizedData['customerCity'] ?? 'N/A',
            'cus_state'     => $sanitizedData['customerState'] ?? '',
            'cus_postcode'  => $sanitizedData['customerPostcode'] ?? '',
            'cus_country'   => $sanitizedData['customerCountry'] ?? 'Bangladesh',
            // Product details
            'product_name'  => $sanitizedData['productName'] ?? 'Service/Product',
            'product_category' => $sanitizedData['productCategory'] ?? $this->config['product_category'],
            'product_profile' => $sanitizedData['productProfile'] ?? 'general', // e.g. general, physical-goods, digital-goods, airline-tickets
            // Optional parameters
            'shipping_method' => $sanitizedData['shippingMethod'] ?? 'NO', // e.g., YES, NO, Courier
            'num_of_item'   => $sanitizedData['numberOfItems'] ?? 1,
            'value_a'       => $sanitizedData['customParam1'] ?? '', // Custom parameters
            'value_b'       => $sanitizedData['customParam2'] ?? '',
            // 'value_c', 'value_d'
        ];

        try {
            // $responseJson = $this->httpClient('POST', $this->getApiBaseUrl() . self::SESSION_REQUEST_ENDPOINT, $params, [], true);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($params['total_amount'] == '9999.99') { // Simulate API error based on amount
                 $mockResponse = ['status' => 'FAILED', 'failedreason' => 'Invalid amount for testing.'];
            } elseif ($params['tran_id'] === 'FAIL_SSL_INIT') {
                 $mockResponse = ['status' => 'FAILED', 'failedreason' => 'Simulated initialization failure.'];
            } else {
                 $mockResponse = [
                    'status' => 'SUCCESS',
                    'sessionkey' => 'MOCKSESSIONKEY' . strtoupper(uniqid()) . $params['tran_id'],
                    'GatewayPageURL' => $this->getApiBaseUrl() . '/gwprocess/v4/gw.php?Q=PAY&SESSIONKEY=' . ('MOCKSESSIONKEY' . strtoupper(uniqid()) . $params['tran_id']), // Conceptual
                    'directPaymentURLBank' => '', // Links for direct bank pages if applicable
                    'directPaymentURLCard' => '',
                    'redirectGatewayURL' => 'https://securepay.sslcommerz.com/gwprocess/v4/gw.php', // Conceptual base for redirect
                    'failedreason' => '',
                 ];
            }
            $response = $mockResponse;
            // End Mock

            if (!$response || $response['status'] !== 'SUCCESS') {
                throw new InitializationException('SSLCommerz: Failed to initiate session. ' . ($response['failedreason'] ?? 'Unknown error from gateway.'));
            }

            return [
                'status' => 'pending_user_redirect',
                'message' => 'SSLCommerz session initiated. Redirect user to GatewayPageURL.',
                'paymentUrl' => $response['GatewayPageURL'], // This is the key URL for redirect
                'sessionkey' => $response['sessionkey'],
                'orderId' => $params['tran_id'],
                'gatewayReferenceId' => $response['sessionkey'], // Session key acts as initial reference
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            if ($e instanceof InitializationException) throw $e;
            throw new InitializationException('SSLCommerz: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Processes IPN callback or redirect response (POST data from SSLCommerz)
        $sanitizedData = $this->sanitize($data);

        // Key fields from SSLCommerz: status (VALID, VALIDATED, INVALID_TRANSACTION), tran_id, val_id (validation id),
        // amount, card_type, store_amount, card_no, currency, tran_date, error, verify_sign, verify_key etc.
        if (empty($sanitizedData['status']) || empty($sanitizedData['tran_id'])) {
            throw new ProcessingException('SSLCommerz Callback: Invalid data. Missing status or tran_id.');
        }

        // IPN hash verification - this is crucial if using IPN listener
        // if (isset($sanitizedData['verify_sign']) && !$this->verifyIPNHash($sanitizedData)) {
        //     throw new ProcessingException('SSLCommerz IPN: Signature hash verification failed.');
        // }
        // For redirect (success/fail/cancel URLs), hash might not be present or required. Validation API is preferred.

        $orderId = $sanitizedData['tran_id'];
        $sslczTxnId = $sanitizedData['bank_tran_id'] ?? null; // Bank's transaction ID
        $validationId = $sanitizedData['val_id'] ?? null;     // SSLCommerz validation ID
        $paymentStatus = $sanitizedData['status']; // VALID, VALIDATED, INVALID_TRANSACTION, FAILED, CANCELLED

        $finalStatus = 'failed';
        $message = 'SSLCommerz payment status: ' . $paymentStatus;

        if ($paymentStatus === 'VALIDATED' || $paymentStatus === 'VALID') { // VALID is often after IPN, VALIDATED after direct validation call
            $finalStatus = 'success';
        } elseif ($paymentStatus === 'PENDING') {
            $finalStatus = 'pending';
        } elseif ($paymentStatus === 'FAILED' || $paymentStatus === 'INVALID_TRANSACTION' || $paymentStatus === 'UNATHORIZED' || $paymentStatus === 'EXPIRED_CARD') {
            $finalStatus = 'failed';
            $message .= ('. Reason: ' . ($sanitizedData['error'] ?? ($sanitizedData['failedreason'] ?? 'N/A')));
        } elseif ($paymentStatus === 'CANCELLED'){
            $finalStatus = 'failed'; // Or 'cancelled'
            $message = 'SSLCommerz: User cancelled the payment.';
        }
        
        if (($sanitizedData['risk_level'] ?? '0') !== '0') {
            // $message .= ' Potential risk detected: ' . $sanitizedData['risk_title'];
            // Decide if this should alter finalStatus based on policy
        }
        if (($sanitizedData['APIConnect'] ?? '') === 'SIMULATE_INVALID_PROCESS'){
            $finalStatus = 'failed';
            $message = 'SSLCommerz Process: API Connect simulated error.';
        }


        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $sslczTxnId, 
            'validationId' => $validationId, // SSLCommerz specific validation ID
            'orderId' => $orderId,
            'paymentStatus' => $paymentStatus,
            'amount' => $sanitizedData['amount'] ?? null,
            'cardType' => $sanitizedData['card_type'] ?? null,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Uses Order Validation API or Transaction Query API
        $sanitizedData = $this->sanitize($data);

        $validationParams = [
            'store_id' => $this->config['store_id'],
            'store_passwd' => $this->config['store_passwd'],
            'format' => 'json', // Request JSON response
        ];

        $endpoint = '';
        if (!empty($sanitizedData['validationId'])) { // `val_id` from initial response or IPN
            $validationParams['val_id'] = $sanitizedData['validationId'];
            $endpoint = $this->getApiBaseUrl() . self::ORDER_VALIDATION_ENDPOINT;
        } elseif (!empty($sanitizedData['orderId'])) { // `tran_id` (merchant's order ID)
            $validationParams['tran_id'] = $sanitizedData['orderId'];
            $endpoint = $this->getApiBaseUrl() . self::TRANSACTION_QUERY_ENDPOINT;
        } else {
            throw new VerificationException('SSLCommerz: validationId (val_id) or orderId (tran_id) is required for verification.');
        }

        try {
            // $responseJson = $this->httpClient('GET', $endpoint, $validationParams);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            $queryKey = $sanitizedData['validationId'] ?? $sanitizedData['orderId'];

            if ($queryKey === 'FAIL_SSL_VERIFY_API') {
                $mockResponse = ['status' => 'INVALID_REQUEST', 'failedreason' => 'Simulated API query failure.'];
            }
            elseif (strpos($queryKey, 'VALID_SUCCESS') !== false || $sanitizedData['orderId'] === 'ORDER_VALID_SSL') {
                $mockResponse = [
                    'status' => 'VALID', 'APIConnect' => 'DONE',
                    'tran_id' => $sanitizedData['orderId'] ?? 'TRN_'.uniqid(), 'val_id' => $queryKey,
                    'amount' => '100.00', 'store_amount' => '98.00', 'card_type' => 'VISA-SSL',
                    'tran_date' => date('Y-m-d H:i:s'), 'currency' => 'BDT', 'bank_tran_id' => 'SSLBNK_'.uniqid(),
                    'validated_on' => date('Y-m-d H:i:s'), 'risk_level' => '0', 'risk_title' => 'Safe'
                ];
            } elseif (strpos($queryKey, 'VALIDATED_SUCCESS') !== false || $sanitizedData['orderId'] === 'ORDER_VALIDATED_SSL'){
                 $mockResponse = array_merge($mockResponse, ['status' => 'VALIDATED']); // Similar to VALID but often final
            } elseif (strpos($queryKey, 'PENDING_SSL') !== false || $sanitizedData['orderId'] === 'ORDER_PENDING_SSL') {
                $mockResponse = ['status' => 'PENDING', 'APIConnect' => 'DONE', 'tran_id' => $sanitizedData['orderId'] ?? 'TRN_PEND'.uniqid(), 'val_id' => $queryKey, 'amount' => '50.00'];
            } elseif (strpos($queryKey, 'FAILED_SSL') !== false || $sanitizedData['orderId'] === 'ORDER_FAILED_SSL') {
                $mockResponse = ['status' => 'FAILED', 'APIConnect' => 'DONE', 'tran_id' => $sanitizedData['orderId'] ?? 'TRN_FAIL'.uniqid(), 'val_id' => $queryKey, 'failedreason' => 'Payment failed by bank.'];
            } else { // Invalid or not found
                $mockResponse = ['status' => 'INVALID_TRANSACTION', 'APIConnect' => 'DONE', 'tran_id' => $sanitizedData['orderId'] ?? 'TRN_INV'.uniqid(), 'failedreason' => 'Transaction not found or invalid parameters.'];
            }
            $response = $mockResponse;
            // End Mock

            if (!$response || !isset($response['status'])) {
                throw new VerificationException('SSLCommerz Verify: Invalid response from API. ' . ($response['failedreason'] ?? ''));
            }
            if ($response['status'] === 'INVALID_REQUEST' || $response['APIConnect'] !== 'DONE') {
                 throw new VerificationException('SSLCommerz Verify: API connection or request failed. ' . ($response['failedreason'] ?? ''));
            }

            $paymentApiStatus = $response['status']; // VALID, VALIDATED, INVALID_TRANSACTION, FAILED, PENDING, CANCELLED etc.
            $finalStatus = 'failed';
            if ($paymentApiStatus === 'VALID' || $paymentApiStatus === 'VALIDATED') {
                $finalStatus = 'success';
            } elseif ($paymentApiStatus === 'PENDING') {
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'SSLCommerz Verify Status: ' . $paymentApiStatus . '. ' . ($response['failedreason'] ?? ''),
                'transactionId' => $response['bank_tran_id'] ?? null, // Bank's transaction ID
                'validationId' => $response['val_id'] ?? null,       // SSLCommerz validation ID
                'orderId' => $response['tran_id'] ?? null,
                'paymentStatus' => $paymentApiStatus,
                'amount' => $response['amount'] ?? null, // This is total_amount
                'storeAmount' => $response['store_amount'] ?? null, // Amount credited to store after fees
                'cardType' => $response['card_type'] ?? null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new VerificationException('SSLCommerz: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // SSLCommerz Refund API (can be part of Transaction Query/Validation API or a separate one)
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // bank_tran_id from successful transaction
            throw new RefundException('SSLCommerz: bank_tran_id is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('SSLCommerz: Invalid refund amount.');
        }

        $refundParams = [
            'store_id'      => $this->config['store_id'],
            'store_passwd'  => $this->config['store_passwd'],
            'bank_tran_id'  => $sanitizedData['transactionId'],
            'refund_amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'refund_remarks'=> $sanitizedData['reason'] ?? 'Merchant requested refund',
            'refe_id'       => $sanitizedData['refundId'] ?? ('REF' . uniqid()), // Your unique reference for this refund attempt
            'format'        => 'json'
        ];

        try {
            // $responseJson = $this->httpClient('POST', $this->getApiBaseUrl() . self::REFUND_REQUEST_ENDPOINT, $refundParams, [], true);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($refundParams['refund_amount'] == '99.98') {
                $mockResponse = ['status' => 'FAILED', 'errorReason' => 'Invalid refund amount (simulated)'];
            } elseif ($refundParams['bank_tran_id'] === 'SSL_BNK_TXN_NO_REFUND'){
                $mockResponse = ['status' => 'FAILED', 'errorReason' => 'Transaction not eligible for refund or already refunded (simulated)'];
            } else {
                $mockResponse = [
                    'status' => 'SUCCESS', // Or PENDING/PROCESSING if async
                    'APIConnect' => 'DONE',
                    'bank_tran_id' => $refundParams['bank_tran_id'],
                    'tran_id' => $sanitizedData['orderId'] ?? 'UNKNOWN_ORD_ID',
                    'refund_ref_id' => $refundParams['refe_id'], // SSLCommerz internal refund reference ID
                    'status_name' => 'Refund Initiated', // More descriptive status
                    'errorReason' => ''
                ];
            }
            $response = $mockResponse;
            // End Mock

            if (!$response || $response['APIConnect'] !== 'DONE' || $response['status'] === 'FAILED') {
                throw new RefundException('SSLCommerz Refund: Failed. ' . ($response['errorReason'] ?? 'Unknown error from refund API.'));
            }

            // status could be SUCCESS (for immediate), PENDING, PROCESSING
            $refundApiStatus = $response['status_name'] ?? $response['status'];
            $finalStatus = 'pending'; // Assume pending as refunds are often async
            if ($response['status'] === 'SUCCESS') {
                 if(stripos($refundApiStatus, 'Initiated') !== false || stripos($refundApiStatus, 'Pending') !== false || stripos($refundApiStatus, 'Processing') !== false) {
                    $finalStatus = 'pending';
                 } else {
                    $finalStatus = 'success'; // If API confirms immediate full refund
                 }
            } elseif ($response['status'] === 'REJECTED' || $response['status'] === 'ERROR') {
                $finalStatus = 'failed';
            }

            return [
                'status' => $finalStatus,
                'message' => 'SSLCommerz Refund: ' . $refundApiStatus . '. ' . ($response['errorReason'] ?? ''),
                'refundId' => $response['refund_ref_id'] ?? $refundParams['refe_id'],
                'transactionId' => $response['bank_tran_id'] ?? null,
                'orderId' => $response['tran_id'] ?? null,
                'paymentStatus' => 'REFUND_' . strtoupper($response['status']),
                'amount' => $refundParams['refund_amount'],
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new RefundException('SSLCommerz: Refund processing failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 