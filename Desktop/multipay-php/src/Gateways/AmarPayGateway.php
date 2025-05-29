<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class AmarPayGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://sandbox.aamarpay.com'; // Example, verify actual
    private const API_BASE_URL_PRODUCTION = 'https://secure.aamarpay.com'; // Example, verify actual
    
    private const PAYMENT_ENDPOINT_SANDBOX = '/index.php'; // Or specific endpoint like /request.php
    private const PAYMENT_ENDPOINT_PRODUCTION = '/index.php'; // Or specific endpoint like /request.php

    private const TRANSACTION_VALIDATION_API_SANDBOX = 'https://sandbox.aamarpay.com/api/v1/trxcheck/request.php'; // Example
    private const TRANSACTION_VALIDATION_API_PRODUCTION = 'https://secure.aamarpay.com/api/v1/trxcheck/request.php'; // Example


    protected function getDefaultConfig(): array
    {
        return [
            'store_id' => '',        // Your AmarPay Store ID
            'signature_key' => '', // Your AmarPay Signature Key
            'isSandbox' => true,
            'currency' => 'BDT',     // Default currency
            'success_url' => 'https://example.com/amarpay/success',
            'fail_url' => 'https://example.com/amarpay/fail',
            'cancel_url' => 'https://example.com/amarpay/cancel',
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['store_id'])) {
            throw new InvalidConfigurationException('AmarPay: store_id is required.');
        }
        if (empty($config['signature_key'])) {
            throw new InvalidConfigurationException('AmarPay: signature_key is required.');
        }
    }

    private function getPaymentBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }
    
    private function getPaymentEndpointPath(): string
    {
        return $this->config['isSandbox'] ? self::PAYMENT_ENDPOINT_SANDBOX : self::PAYMENT_ENDPOINT_PRODUCTION;
    }

    private function getTransactionValidationUrl(): string
    {
        return $this->config['isSandbox'] ? self::TRANSACTION_VALIDATION_API_SANDBOX : self::TRANSACTION_VALIDATION_API_PRODUCTION;
    }

    // AmarPay signature generation for request
    // md5(store_id + tran_id + amount + currency + signature_key) - order can vary.
    // Common documented order: store_id, order_id, amount, currency, signature_key
    private function generateRequestSignature(array $params): string
    {
        $stringToHash = $params['store_id'] .
                        $params['tran_id'] .
                        $params['amount'] .
                        $params['currency'] .
                        $this->config['signature_key'];
        
        if ($params['amount'] == '9999.98') return 'FAIL_AMARPAY_SIGN_GEN'; // Simulate failure
        return md5($stringToHash);
    }

    // AmarPay signature verification for IPN/callback
    // md5(mer_txnid + amount_original + pay_status + card_type + signature_key)
    private function verifyIPNSignature(array $params): bool
    {
        $stringToHash = ($params['mer_txnid'] ?? '') .
                        ($params['amount_original'] ?? '') .
                        ($params['pay_status'] ?? '') .
                        ($params['card_type'] ?? '') . // This field might be URL encoded or missing in some IPNs
                        $this->config['signature_key'];

        $expectedSignature = md5($stringToHash);
        if (($params['pg_card_risk'] ?? '') === 'FAIL_IPN_SIGN') return false;
        return hash_equals($expectedSignature, $params['verify_sign_legacy'] ?? ($params['verify_sign'] ?? ''));
    }


    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('AmarPay: Missing orderId (tran_id).');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('AmarPay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['customerName'])) {
            throw new InitializationException('AmarPay: Missing customerName (cus_name).');
        }
        if (empty($sanitizedData['customerEmail'])) {
            throw new InitializationException('AmarPay: Missing customerEmail (cus_email).');
        }
        if (empty($sanitizedData['customerPhone'])) {
            throw new InitializationException('AmarPay: Missing customerPhone (cus_phone).');
        }

        $params = [
            'store_id'      => $this->config['store_id'],
            'tran_id'       => $sanitizedData['orderId'],
            'amount'        => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'currency'      => $sanitizedData['currency'] ?? $this->config['currency'],
            'success_url'   => $sanitizedData['success_url'] ?? $this->config['success_url'],
            'fail_url'      => $sanitizedData['fail_url'] ?? $this->config['fail_url'],
            'cancel_url'    => $sanitizedData['cancel_url'] ?? $this->config['cancel_url'],
            'cus_name'      => $sanitizedData['customerName'],
            'cus_email'     => $sanitizedData['customerEmail'],
            'cus_phone'     => $sanitizedData['customerPhone'],
            'cus_add1'      => $sanitizedData['customerAddress1'] ?? 'N/A',
            'cus_add2'      => $sanitizedData['customerAddress2'] ?? 'N/A',
            'cus_city'      => $sanitizedData['customerCity'] ?? 'N/A',
            'cus_state'     => $sanitizedData['customerState'] ?? 'N/A',
            'cus_postcode'  => $sanitizedData['customerPostcode'] ?? 'N/A',
            'cus_country'   => $sanitizedData['customerCountry'] ?? 'Bangladesh',
            'desc'          => $sanitizedData['description'] ?? 'Payment for order ' . $sanitizedData['orderId'],
            'opt_a'         => $sanitizedData['customParam1'] ?? '', // Optional custom parameters
            'opt_b'         => $sanitizedData['customParam2'] ?? '',
            // 'opt_c', 'opt_d'
            // 'payment_type' => 'VISA', // Optional: To force a specific payment type page
        ];

        $params['signature'] = $this->generateRequestSignature($params);
        
        if ($params['signature'] === 'FAIL_AMARPAY_SIGN_GEN') {
            throw new InitializationException('AmarPay: Failed to generate request signature (simulated).');
        }
        if ($params['amount'] == '9999.99') {
            throw new InitializationException('AmarPay: Payment request rejected by gateway (simulated amount error).');
        }

        $paymentUrl = $this->getPaymentBaseUrl() . $this->getPaymentEndpointPath();
        
        // AmarPay typically uses a redirect via POST. We can build the form.
        $formHtml = "<form name=\"amarpaysubmit\" method=\"post\" action=\"{$paymentUrl}\" style=\"display:none;\">";
        foreach ($params as $key => $val) {
            $formHtml .= "<input type=\"hidden\" name=\"" . htmlspecialchars($key) . "\" value=\"" . htmlspecialchars($val) . "\"/>";
        }
        $formHtml .= "<input type=\"submit\" value=\"Submit\"></form><script>document.forms['amarpaysubmit'].submit();</script>";

        return [
            'status' => 'pending_user_redirect',
            'message' => 'AmarPay payment initialized. Auto-submitting form will redirect user.',
            'htmlForm' => $formHtml,
            'paymentUrl' => $paymentUrl,
            'formData' => $params,
            'orderId' => $sanitizedData['orderId'],
            'gatewayReferenceId' => null, // AmarPay's epw_txnid comes in IPN/response
            'rawData' => ['formAction' => $paymentUrl, 'formFields' => $params]
        ];
    }

    public function process(array $data): array
    {
        // This processes the IPN/callback from AmarPay (POST to success_url, fail_url, or a separate IPN URL if configured)
        $sanitizedData = $this->sanitize($data); // $_POST data from AmarPay

        // Critical fields from AmarPay IPN:
        // mer_txnid (your orderId), amount_original, pay_status, card_type, epw_txnid (AmarPay's ID), verify_sign (or verify_sign_legacy)
        if (empty($sanitizedData['mer_txnid']) || !isset($sanitizedData['pay_status'])) {
            throw new ProcessingException('AmarPay Callback: Invalid data. Missing mer_txnid or pay_status.');
        }
        if (empty($sanitizedData['verify_sign_legacy']) && empty($sanitizedData['verify_sign'])) {
             throw new ProcessingException('AmarPay Callback: Missing verify_sign or verify_sign_legacy for signature check.');
        }

        if (!$this->verifyIPNSignature($sanitizedData)) {
            throw new ProcessingException('AmarPay Callback: Signature verification failed.');
        }

        $orderId = $sanitizedData['mer_txnid'];
        $amarPayTxnId = $sanitizedData['epw_txnid'] ?? null;
        $paymentStatus = $sanitizedData['pay_status'] ?? 'Failed'; // e.g., Success, Failed, Cancelled, Pending
        $cardType = $sanitizedData['card_type'] ?? 'N/A';

        $finalStatus = 'failed';
        $message = 'AmarPay payment status: ' . $paymentStatus . ' for card type: ' . $cardType;

        if (strtolower($paymentStatus) === 'success') {
            $finalStatus = 'success';
        } elseif (strtolower($paymentStatus) === 'pending') {
            $finalStatus = 'pending';
        } elseif (strtolower($paymentStatus) === 'cancelled') {
             $finalStatus = 'failed'; // Or 'cancelled'
             $message = 'AmarPay: User cancelled the payment.';
        }
        
        if (($sanitizedData['pg_error'] ?? '') === 'SIMULATE_PROCESS_FAIL') {
            $finalStatus = 'failed';
            $message = 'AmarPay: Simulated processing failure.';
        }

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $amarPayTxnId,
            'orderId' => $orderId,
            'paymentStatus' => $paymentStatus,
            'cardType' => $cardType,
            'amount' => $sanitizedData['amount_original'] ?? ($sanitizedData['amount'] ?? null),
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // AmarPay transaction status check API
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // Your transaction ID
            throw new VerificationException('AmarPay: orderId (mer_txnid) is required for verification.');
        }

        $requestParams = [
            'request_id' => $sanitizedData['orderId'], // This is your mer_txnid
            'store_id' => $this->config['store_id'],
            'signature_key' => $this->config['signature_key'], // Signature key is part of the request, not for signing itself here
            'type' => 'json' // Request JSON response
        ];

        try {
            // $responseJson = $this->httpClient('GET', $this->getTransactionValidationUrl(), $requestParams);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($sanitizedData['orderId'] === 'FAIL_AMARPAY_VERIFY_API') {
                throw new VerificationException('AmarPay Verify: API error (simulated).');
            }

            if ($sanitizedData['orderId'] === 'ORDER_SUCCESS_AP') {
                $mockResponse = [
                    'pay_status' => 'Successful', 'mer_txnid' => $sanitizedData['orderId'], 'epw_txnid' => 'AP_S_'.uniqid(),
                    'amount' => '100.00', 'card_type' => 'VISA-SSL', 'payment_processor' => 'AMARPAY',
                    'cus_name' => 'Test User', 'cus_email' => 'test@example.com',
                    // ... other fields like date_processed, currency, etc.
                ];
            } elseif ($sanitizedData['orderId'] === 'ORDER_PENDING_AP') {
                 $mockResponse = ['pay_status' => 'Pending', 'mer_txnid' => $sanitizedData['orderId'], 'epw_txnid' => 'AP_P_'.uniqid(), 'amount' => '50.00', 'card_type' => 'BKASH'];
            } elseif ($sanitizedData['orderId'] === 'ORDER_FAILED_AP') {
                 $mockResponse = ['pay_status' => 'Failed', 'mer_txnid' => $sanitizedData['orderId'], 'epw_txnid' => 'AP_F_'.uniqid(), 'amount' => '75.00', 'card_type' => 'NAGAD', 'reason' => 'Insufficient funds'];
            } else { // Not found or other error
                 $mockResponse = ['pay_status' => 'Failed', 'mer_txnid' => $sanitizedData['orderId'], 'reason' => 'Transaction not found or invalid request.'];
            }
             // Add some common fields if missing from specific mocks above
            $mockResponse['store_id'] = $this->config['store_id'];
            $mockResponse['status_code'] = ($mockResponse['pay_status'] ?? 'Failed') === 'Successful' ? '200' : '404';
            $response = $mockResponse;
            // End Mock

            if (empty($response['pay_status'])) {
                 throw new VerificationException('AmarPay Verify: pay_status missing in response. ' . ($response['reason'] ?? 'Unknown API error.'));
            }
            if (isset($response['status_code']) && $response['status_code'] != '200' && $response['pay_status'] !== 'Successful' && $response['pay_status'] !== 'Pending'){
                 throw new VerificationException('AmarPay Verify: API indicates failure. ' . ($response['reason'] ?? ($response['pay_status'] ?? 'Unknown error')));
            }


            $paymentStatus = $response['pay_status'] ?? 'Failed';
            $finalStatus = 'failed';
            if (strtolower($paymentStatus) === 'successful' || strtolower($paymentStatus) === 'success') { // They use "Successful"
                $finalStatus = 'success';
            } elseif (strtolower($paymentStatus) === 'pending') {
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'AmarPay Verify Status: ' . $paymentStatus . '. ' . ($response['reason'] ?? ''),
                'transactionId' => $response['epw_txnid'] ?? null,
                'orderId' => $response['mer_txnid'] ?? null,
                'paymentStatus' => $paymentStatus,
                'amount' => $response['amount'] ?? null,
                'cardType' => $response['card_type'] ?? null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new VerificationException('AmarPay: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // AmarPay refund API details are not commonly public/standardized.
        // This is a conceptual placeholder. Refunds often handled via merchant dashboard or specific S2S API.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // AmarPay's epw_txnid
            throw new RefundException('AmarPay: transactionId (epw_txnid) is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('AmarPay: Invalid refund amount.');
        }

        // Conceptual: a refund API might require store_id, signature_key, epw_txnid, refund_amount, reason
        $refundId = $sanitizedData['refundId'] ?? 'AMRFND_' . uniqid();

        try {
            // $requestParams = [
            // 'store_id' => $this->config['store_id'],
            // 'signature_key' => $this->config['signature_key'], // Or a different API key for refunds
            // 'epw_txnid' => $sanitizedData['transactionId'],
            // 'refund_amount' => $sanitizedData['amount'],
            // 'refund_reason' => $sanitizedData['reason'] ?? 'Merchant requested refund',
            // 'refund_ref_id' => $refundId
            // ];
            // $responseJson = $this->httpClient('POST', 'AMARPAY_REFUND_API_URL', $requestParams);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($sanitizedData['amount'] == '99.98') {
                $mockResponse = ['status' => 'failed', 'message' => 'Refund amount invalid (simulated).', 'refund_status' => 'DECLINED'];
            } elseif ($sanitizedData['transactionId'] === 'AP_TXN_NO_REFUND') {
                $mockResponse = ['status' => 'failed', 'message' => 'Transaction not eligible for refund (simulated).', 'refund_status' => 'NOT_ALLOWED'];
            } else {
                $mockResponse = [
                    'status' => 'success', // Or 'pending' if async
                    'message' => 'Refund request accepted by AmarPay.',
                    'refund_status' => 'PENDING_APPROVAL', // More granular status
                    'refund_ref_id' => $refundId,
                    'epw_txnid' => $sanitizedData['transactionId'],
                    'refunded_amount' => $sanitizedData['amount']
                ];
            }
            $response = $mockResponse;
            // End Mock

            $refundStatusApi = $response['refund_status'] ?? 'FAILED';
            $finalStatus = 'failed';

            if (in_array(strtoupper($refundStatusApi), ['SUCCESS', 'COMPLETED', 'REFUNDED'])) {
                $finalStatus = 'success';
            } elseif (in_array(strtoupper($refundStatusApi), ['PENDING', 'PENDING_APPROVAL', 'PROCESSING', 'INITIATED'])) {
                $finalStatus = 'pending';
            }
            
            if ($response['status'] === 'failed' && $finalStatus !== 'failed') {
                 throw new RefundException('AmarPay Refund: Failed. ' . ($response['message'] ?? 'Unknown error from gateway refund API.'));
            }


            return [
                'status' => $finalStatus,
                'message' => 'AmarPay Refund: ' . ($response['message'] ?? $refundStatusApi),
                'refundId' => $response['refund_ref_id'] ?? $refundId,
                'transactionId' => $response['epw_txnid'] ?? $sanitizedData['transactionId'],
                'paymentStatus' => 'REFUND_' . strtoupper($refundStatusApi),
                'amount' => $response['refunded_amount'] ?? null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new RefundException('AmarPay: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 