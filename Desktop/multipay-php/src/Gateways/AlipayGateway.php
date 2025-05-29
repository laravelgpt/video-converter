<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class AlipayGateway extends PaymentGateway
{
    // Alipay API URLs (vary based on product: cross-border, in-app, web)
    private const API_BASE_URL_SANDBOX = 'https://openapi.alipaydev.com/gateway.do'; // Example for sandbox
    private const API_BASE_URL_PRODUCTION = 'https://openapi.alipay.com/gateway.do'; // Example for production

    protected function getDefaultConfig(): array
    {
        return [
            'app_id' => '',              // Your Alipay App ID
            'merchant_private_key' => '', // Your RSA2 Private Key (PKCS1 or PKCS8)
            'alipay_public_key' => '',   // Alipay's Public Key (for verifying responses)
            'charset' => 'UTF-8',
            'sign_type' => 'RSA2',
            'gateway_url' => null,       // Optional: override default gateway URL
            'isSandbox' => true,
            'timeout' => 60,
            'notify_url' => 'https://example.com/alipay/notify', // Async notification URL
            'return_url' => 'https://example.com/alipay/return', // Sync return URL for web payments
        ];
    }

    protected function validateConfig(array $config): void
    {
        $requiredKeys = ['app_id', 'merchant_private_key', 'alipay_public_key'];
        foreach ($requiredKeys as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Alipay: {$key} is required.");
            }
        }
        if (!in_array($config['sign_type'], ['RSA', 'RSA2'])) {
            throw new InvalidConfigurationException("Alipay: Invalid sign_type. Must be RSA or RSA2.");
        }
    }

    private function getApiBaseUrl(): string
    {
        if (!empty($this->config['gateway_url'])) {
            return $this->config['gateway_url'];
        }
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    // Conceptual: Generate signature for request parameters
    private function generateSignature(array $params): string
    {
        // 1. Remove 'sign' and any empty value parameters
        // 2. Sort parameters by key
        // 3. Concatenate into query string format (key1=value1&key2=value2)
        // 4. Sign the string with merchant_private_key using specified sign_type (RSA/RSA2 with SHA1/SHA256)
        // 5. Base64 encode the signature
        // This is a complex process, for mock, we'll simplify
        if (($params['biz_content']['total_amount'] ?? 0) == 9999.98) return 'FAIL_SIGN_GENERATION'; // Simulate failure
        return 'MOCK_ALIPAY_SIGNATURE_FOR_' . md5(json_encode($params) . $this->config['merchant_private_key']);
    }

    // Conceptual: Verify signature of Alipay's asynchronous notification
    private function verifySignature(array $params, string $signature): bool
    {
        if ($signature === 'FAIL_ALIPAY_SIGN_VERIFY') return false;
        // 1. Remove 'sign' and 'sign_type' from params
        // 2. Sort parameters by key
        // 3. Concatenate into query string format
        // 4. Verify with alipay_public_key and sign_type
        // Simplified mock
        $expectedSignature = 'MOCK_ALIPAY_SIGNATURE_FOR_NOTIFICATION_' . md5(json_encode($params) . $this->config['alipay_public_key']);
        // In a real scenario, notification might have its own specific signature structure
        // For testing, let's assume if a known "good" signature is passed for a specific trade_no, it's valid
        if (isset($params['trade_no']) && $signature === 'VALID_SIGN_FOR_' . $params['trade_no']) return true;
        if (isset($params['out_trade_no']) && $signature === 'VALID_SIGN_FOR_OUT_' . $params['out_trade_no']) return true;
        
        // Fallback for general mock, assuming if not explicitly failing, it's okay.
        return true; 
    }
    
    private function buildRequestParams(string $method, array $bizContent, array $extraParams = []): array
    {
        $commonParams = [
            'app_id' => $this->config['app_id'],
            'method' => $method,
            'format' => 'JSON', // Typically JSON
            'charset' => $this->config['charset'],
            'sign_type' => $this->config['sign_type'],
            'timestamp' => date('Y-m-d H:i:s'),
            'version' => '1.0', // API version
            'notify_url' => $this->config['notify_url'], // For transaction-related APIs
        ];
        if (isset($extraParams['return_url'])) {
            $commonParams['return_url'] = $extraParams['return_url'];
        }

        $commonParams['biz_content'] = json_encode($bizContent); // Biz content must be JSON string
        $commonParams['sign'] = $this->generateSignature($commonParams);
        return $commonParams;
    }


    public function initialize(array $data): array
    {
        // Example: alipay.trade.page.pay (PC Web), alipay.trade.app.pay (Mobile App), alipay.trade.wap.pay (Mobile Web)
        // This mock simulates alipay.trade.page.pay
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // out_trade_no
            throw new InitializationException('Alipay: Missing orderId (out_trade_no).');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Alipay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['subject'])) { // Subject of the transaction
            throw new InitializationException('Alipay: Missing subject for the transaction.');
        }

        $bizContent = [
            'out_trade_no' => $sanitizedData['orderId'],
            'total_amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'subject' => $sanitizedData['subject'],
            'product_code' => 'FAST_INSTANT_TRADE_PAY', // For PC Web payment
            // 'qr_pay_mode', 'qrcode_width' for alipay.trade.precreate (QR code payment)
        ];
        
        // Specific product code for different types of payments
        $paymentMethod = $sanitizedData['paymentMethod'] ?? 'page'; // page, app, wap, precreate (QR)
        $apiMethod = '';
        
        switch ($paymentMethod) {
            case 'app':
                $apiMethod = 'alipay.trade.app.pay';
                // For app pay, response is an order string for SDK, not a redirect.
                break;
            case 'wap':
                $apiMethod = 'alipay.trade.wap.pay';
                $bizContent['product_code'] = 'QUICK_WAP_WAY';
                break;
            case 'precreate': // Generate QR code
                $apiMethod = 'alipay.trade.precreate';
                unset($bizContent['product_code']); // Not needed for precreate
                break;
            case 'page':
            default:
                $apiMethod = 'alipay.trade.page.pay';
                break;
        }

        $requestParams = $this->buildRequestParams(
            $apiMethod, 
            $bizContent,
            ['return_url' => $sanitizedData['returnUrl'] ?? $this->config['return_url']]
        );
        
        if ($requestParams['sign'] === 'FAIL_SIGN_GENERATION') {
            throw new InitializationException('Alipay: Failed to generate request signature (simulated).');
        }

        try {
            // For alipay.trade.page.pay or alipay.trade.wap.pay, the "response" is not from an API call.
            // Instead, you construct a form and auto-submit it, or redirect the user with GET parameters.
            // Alipay SDKs often handle this.
            // The `httpClient` would POST these $requestParams to the Alipay gateway.
            // Alipay then returns an HTML page or redirects.
            
            // For alipay.trade.app.pay, the `execute` method of SDK returns order string.
            // For alipay.trade.precreate, the API call returns a QR code URL.

            // Mocking this process:
            if ($bizContent['total_amount'] == '9999.99') { // Simulate API rejection based on amount
                 throw new InitializationException('Alipay: API rejected payment request (simulated amount error).');
            }

            $gatewayUrl = $this->getApiBaseUrl();
            
            if ($apiMethod === 'alipay.trade.app.pay') {
                // SDK would return an order string
                $mockOrderString = 'MOCK_ALIPAY_APP_PAY_ORDER_STRING_FOR_' . $sanitizedData['orderId'];
                return [
                    'status' => 'pending_client_sdk_action',
                    'message' => 'Alipay app payment initialized. Pass orderString to client SDK.',
                    'orderString' => $mockOrderString,
                    'orderId' => $sanitizedData['orderId'],
                    'gatewayReferenceId' => null, // Alipay trade_no comes later
                    'rawData' => ['orderString' => $mockOrderString, 'params' => $requestParams]
                ];
            } elseif ($apiMethod === 'alipay.trade.precreate') {
                 // Simulate direct API call for precreate
                // $response = $this->httpClient('POST', $gatewayUrl, $requestParams); // This is a direct API call
                // Mocked response for precreate
                $mockQrCode = 'https://qr.alipay.com/MOCK_QR_' . uniqid();
                $mockApiResponse = [
                    'alipay_trade_precreate_response' => [
                        'code' => '10000', // Success
                        'msg' => 'Success',
                        'out_trade_no' => $sanitizedData['orderId'],
                        'qr_code' => $mockQrCode
                    ],
                    'sign' => 'MOCK_SIGNATURE_FOR_PRECREATE_RESPONSE'
                ];
                 if ($bizContent['total_amount'] == '8888.88') {
                     $mockApiResponse['alipay_trade_precreate_response']['code'] = '40004';
                     $mockApiResponse['alipay_trade_precreate_response']['msg'] = 'Business Failed';
                     $mockApiResponse['alipay_trade_precreate_response']['sub_code'] = 'ACQ.TRADE_HAS_SUCCESS';
                     $mockApiResponse['alipay_trade_precreate_response']['sub_msg'] = 'Transaction already paid';
                     throw new InitializationException('Alipay Precreate Error: Transaction already paid (simulated)');
                 }

                return [
                    'status' => 'pending_user_action', // User needs to scan QR code
                    'message' => 'Alipay QR code generated for payment.',
                    'qrCodeUrl' => $mockApiResponse['alipay_trade_precreate_response']['qr_code'],
                    'orderId' => $sanitizedData['orderId'],
                    'gatewayReferenceId' => null,
                    'rawData' => $mockApiResponse
                ];
            } else { // For page and wap pay
                // The SDK or manual implementation builds a form that auto-submits to $gatewayUrl with $requestParams.
                // The form content can be returned to the client to render.
                $formHtml = "<form name=\"alipaysubmit\" method=\"post\" action=\"" . htmlspecialchars($gatewayUrl) . "?charset=" . $this->config['charset'] . "\" style=\"display:none;\">";
                foreach ($requestParams as $key => $val) {
                    $formHtml .= "<input type=\"hidden\" name=\"{$key}\" value=\"" . htmlspecialchars($val) . "\"/>";
                }
                $formHtml .= "<input type=\"submit\" value=\"Submit\"></form><script>document.forms['alipaysubmit'].submit();</script>";

                return [
                    'status' => 'pending_user_redirect', // User will be redirected by the auto-submitting form
                    'message' => 'Alipay payment initialized. Auto-submitting form will redirect user.',
                    'htmlForm' => $formHtml, // HTML form to auto-submit
                    'paymentUrl' => $gatewayUrl, // URL the form posts to
                    'formData' => $requestParams, // Data for the form
                    'orderId' => $sanitizedData['orderId'],
                    'gatewayReferenceId' => null, 
                    'rawData' => ['formAction' => $gatewayUrl, 'formFields' => $requestParams]
                ];
            }

        } catch (\Exception $e) {
            if ($e instanceof InitializationException) throw $e;
            throw new InitializationException('Alipay: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This processes the asynchronous notification (POST to notify_url) or synchronous return (GET to return_url).
        // $data here is $_POST for notify, or $_GET for return.
        // Asynchronous notification is more reliable for final status.
        $sanitizedData = $this->sanitize($data);

        if (empty($sanitizedData['out_trade_no']) || empty($sanitizedData['trade_no']) || empty($sanitizedData['trade_status'])) {
            throw new ProcessingException('Alipay Callback: Invalid data. Missing out_trade_no, trade_no, or trade_status.');
        }

        // 1. Verify signature (CRITICAL for notify_url)
        $signature = $sanitizedData['sign'] ?? '';
        // In a real scenario, you get all POST data (excluding sign and sign_type for some SDKs) to verify.
        $paramsToVerify = $sanitizedData;
        unset($paramsToVerify['sign'], $paramsToVerify['sign_type']); // sign_type might also be excluded for verification by some SDKs
        
        // For mock, we'll use a simplified check or expect a specific signature for testing
        if (!$this->verifySignature($paramsToVerify, $signature)) {
            if (!empty($this->config['alipay_public_key'])){ // Only fail if public key is set, otherwise assume test without verification for mock
                 throw new ProcessingException('Alipay Callback: Signature verification failed.');
            }
        }

        $orderId = $sanitizedData['out_trade_no'];
        $alipayTradeNo = $sanitizedData['trade_no'];
        $tradeStatus = $sanitizedData['trade_status']; // e.g., TRADE_SUCCESS, TRADE_FINISHED, TRADE_CLOSED, WAIT_BUYER_PAY

        $finalStatus = 'failed';
        $message = 'Alipay payment status: ' . $tradeStatus;

        if ($tradeStatus === 'TRADE_SUCCESS' || $tradeStatus === 'TRADE_FINISHED') {
            // TRADE_FINISHED means irreversible success (e.g., no more refunds possible via API).
            // TRADE_SUCCESS means payment is successful. For most cases, treat both as success.
            $finalStatus = 'success';
        } elseif ($tradeStatus === 'WAIT_BUYER_PAY') {
            $finalStatus = 'pending';
        } elseif ($tradeStatus === 'TRADE_CLOSED') {
            $finalStatus = 'failed'; // Or 'cancelled' if more specific context
            $message .= ' (Transaction closed, e.g. timeout or full refund)';
        }

        // Important: For notify_url, you MUST respond with "success" (literal string) to Alipay, otherwise they keep sending notifications.
        // This should be handled by the calling application after this method returns.

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $alipayTradeNo, // Alipay's transaction ID
            'orderId' => $orderId,             // Your order ID
            'paymentStatus' => $tradeStatus,
            'amount' => $sanitizedData['total_amount'] ?? ($sanitizedData['receipt_amount'] ?? null), // total_amount or receipt_amount
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // alipay.trade.query
        $sanitizedData = $this->sanitize($data);
        // Query by either out_trade_no (your orderId) or trade_no (Alipay's transactionId)
        if (empty($sanitizedData['orderId']) && empty($sanitizedData['transactionId'])) {
            throw new VerificationException('Alipay: Either orderId (out_trade_no) or transactionId (trade_no) is required for query.');
        }

        $bizContent = [];
        if (!empty($sanitizedData['transactionId'])) {
            $bizContent['trade_no'] = $sanitizedData['transactionId'];
        } else {
            $bizContent['out_trade_no'] = $sanitizedData['orderId'];
        }
        
        $requestParams = $this->buildRequestParams('alipay.trade.query', $bizContent);
        if ($requestParams['sign'] === 'FAIL_SIGN_GENERATION') {
            throw new VerificationException('Alipay Query: Failed to generate request signature (simulated).');
        }

        try {
            // $responseJson = $this->httpClient('POST', $this->getApiBaseUrl(), $requestParams); // POST query params
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            $queryKey = $bizContent['trade_no'] ?? $bizContent['out_trade_no'];

            if ($queryKey === 'FAIL_ALIPAY_QUERY') {
                throw new VerificationException('Alipay Query: API error (simulated).');
            }
            
            $alipayTradeQueryResponse = null;
            if ($queryKey === 'ALIPAY_TID_SUCCESS' || $queryKey === 'ORDER_ID_SUCCESS') {
                $alipayTradeQueryResponse = [
                    'code' => '10000', 'msg' => 'Success', 'trade_no' => $queryKey === 'ALIPAY_TID_SUCCESS' ? $queryKey : 'ALIPAY_TRADE_NO_FOR_' . $queryKey,
                    'out_trade_no' => $queryKey === 'ORDER_ID_SUCCESS' ? $queryKey : 'YOUR_ORDER_ID_FOR_' . $queryKey,
                    'trade_status' => 'TRADE_SUCCESS', 'total_amount' => '100.00'
                ];
            } elseif ($queryKey === 'ALIPAY_TID_PENDING' || $queryKey === 'ORDER_ID_PENDING') {
                 $alipayTradeQueryResponse = ['code' => '10000', 'msg' => 'Success', 'trade_no' => 'ALIPAY_TPEND', 'out_trade_no' => 'ORDER_PEND', 'trade_status' => 'WAIT_BUYER_PAY', 'total_amount' => '50.00'];
            } elseif ($queryKey === 'ALIPAY_TID_CLOSED' || $queryKey === 'ORDER_ID_CLOSED') {
                 $alipayTradeQueryResponse = ['code' => '10000', 'msg' => 'Success', 'trade_no' => 'ALIPAY_TCLOSED', 'out_trade_no' => 'ORDER_CLOSED', 'trade_status' => 'TRADE_CLOSED', 'total_amount' => '75.00'];
            } else { // Not found
                $alipayTradeQueryResponse = ['code' => '40004', 'msg' => 'Business Failed', 'sub_code' => 'ACQ.TRADE_NOT_EXIST', 'sub_msg' => 'Transaction not found'];
            }
            $mockResponse['alipay_trade_query_response'] = $alipayTradeQueryResponse;
            $mockResponse['sign'] = 'MOCK_SIGN_FOR_QUERY_RESPONSE_'.md5(json_encode($alipayTradeQueryResponse));
            $response = $mockResponse;
            // End Mocked Response

            $queryResponseData = $response['alipay_trade_query_response'] ?? null;
            if (!$queryResponseData || $queryResponseData['code'] !== '10000') {
                throw new VerificationException('Alipay Query: Failed. ' . ($queryResponseData['sub_msg'] ?? ($queryResponseData['msg'] ?? 'Unknown error')));
            }

            // Optional: Verify signature of query response as well.
            // $this->verifySignature($queryResponseData, $response['sign'] ?? '');

            $tradeStatus = $queryResponseData['trade_status'] ?? '';
            $finalStatus = 'failed';
            if ($tradeStatus === 'TRADE_SUCCESS' || $tradeStatus === 'TRADE_FINISHED') {
                $finalStatus = 'success';
            } elseif ($tradeStatus === 'WAIT_BUYER_PAY') {
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'Alipay Query Status: ' . $tradeStatus . '. ' . ($queryResponseData['msg'] ?? ''),
                'transactionId' => $queryResponseData['trade_no'] ?? null,
                'orderId' => $queryResponseData['out_trade_no'] ?? null,
                'paymentStatus' => $tradeStatus,
                'amount' => $queryResponseData['total_amount'] ?? null,
                'rawData' => $queryResponseData
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Alipay: Transaction query failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // alipay.trade.refund
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Alipay: Invalid or missing amount for refund.');
        }
        // Refund by either out_trade_no (your orderId) or trade_no (Alipay's transactionId)
        if (empty($sanitizedData['orderId']) && empty($sanitizedData['transactionId'])) {
            throw new RefundException('Alipay: Either orderId (out_trade_no) or transactionId (trade_no) is required for refund.');
        }

        $bizContent = [
            'refund_amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'refund_reason' => $sanitizedData['reason'] ?? 'Normal refund',
            'out_request_no' => $sanitizedData['refundId'] ?? ('REFUND_' . uniqid()), // Unique ID for this refund request
        ];
        if (!empty($sanitizedData['transactionId'])) {
            $bizContent['trade_no'] = $sanitizedData['transactionId'];
        } else {
            $bizContent['out_trade_no'] = $sanitizedData['orderId'];
        }

        $requestParams = $this->buildRequestParams('alipay.trade.refund', $bizContent);
        if ($requestParams['sign'] === 'FAIL_SIGN_GENERATION') {
            throw new RefundException('Alipay Refund: Failed to generate request signature (simulated).');
        }

        try {
            // $responseJson = $this->httpClient('POST', $this->getApiBaseUrl(), $requestParams);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            $refundKey = $bizContent['trade_no'] ?? $bizContent['out_trade_no'];
            $alipayTradeRefundResponse = null;

            if ($bizContent['refund_amount'] == '99.99') { // Simulate specific error
                 $alipayTradeRefundResponse = ['code' => '40004', 'msg' => 'Business Failed', 'sub_code' => 'ACQ.REFUND_AMT_NOT_EQUAL_TOTAL', 'sub_msg' => 'Refund amount error'];
            } elseif ($refundKey === 'ALIPAY_TID_NO_REFUND' || $refundKey === 'ORDER_ID_NO_REFUND') {
                 $alipayTradeRefundResponse = ['code' => '40004', 'msg' => 'Business Failed', 'sub_code' => 'ACQ.TRADE_NOT_ALLOW_REFUND', 'sub_msg' => 'Transaction not refundable'];
            } else {
                 $alipayTradeRefundResponse = [
                    'code' => '10000', 'msg' => 'Success', 'trade_no' => $bizContent['trade_no'] ?? ('ALIPAY_TRADE_NO_FOR_REF_' . $bizContent['out_trade_no']),
                    'out_trade_no' => $bizContent['out_trade_no'] ?? ('YOUR_ORDER_ID_FOR_REF_' . $bizContent['trade_no']),
                    'buyer_logon_id' => 'mock***@example.com', 'fund_change' => 'Y', // Y if funds changed
                    'refund_fee' => $bizContent['refund_amount'], // Or actual refunded amount, could differ due to fees
                    'gmt_refund_pay' => date('Y-m-d H:i:s'),
                ];
            }
            $mockResponse['alipay_trade_refund_response'] = $alipayTradeRefundResponse;
            $mockResponse['sign'] = 'MOCK_SIGN_FOR_REFUND_RESPONSE_'.md5(json_encode($alipayTradeRefundResponse));
            $response = $mockResponse;
            // End Mocked Response

            $refundResponseData = $response['alipay_trade_refund_response'] ?? null;
            if (!$refundResponseData || $refundResponseData['code'] !== '10000') {
                // Some refunds might be '10000' but sub_code indicates partial success or async processing.
                // For simplicity, only strict '10000' without error sub_code is full success here.
                // if ($refundResponseData['code'] === '10000' && isset($refundResponseData['sub_code'])) {
                // // Potentially treat as pending or partial success based on sub_code
                // }
                throw new RefundException('Alipay Refund: Failed. ' . ($refundResponseData['sub_msg'] ?? ($refundResponseData['msg'] ?? 'Unknown error')));
            }
            
            // Optional: verify signature of refund response.

            $status = 'success'; // Assume synchronous success if code is 10000 and fund_change Y
            if (($refundResponseData['fund_change'] ?? 'N') !== 'Y') {
                 // This state can mean the refund is accepted but not yet processed, or already refunded.
                 // Check `gmt_refund_pay` and other details. For mock, consider it pending or already done.
                 $status = 'pending'; // Or check if it's a duplicate refund attempt
                 if (isset($refundResponseData['sub_code']) && $refundResponseData['sub_code'] === 'ACQ.REASON_TRADE_REFUND_FEE_ERR') {
                    // This indicates an issue, possibly already refunded or other problem.
                    $status = 'failed';
                 }
            }


            return [
                'status' => $status,
                'message' => 'Alipay Refund: ' . $refundResponseData['msg'] . ($status === 'success' ? '. Fund change: Y.' : '. Fund change: N (may be pending or already refunded).'),
                'refundId' => $bizContent['out_request_no'], // Your refund request ID
                'transactionId' => $refundResponseData['trade_no'] ?? null, // Alipay Transaction ID
                'orderId' => $refundResponseData['out_trade_no'] ?? null,   // Your Order ID
                'paymentStatus' => 'REFUNDED', // Or more granular if API provides
                'amount' => $refundResponseData['refund_fee'] ?? null, // Actual refunded amount
                'rawData' => $refundResponseData
            ];
        } catch (\Exception $e) {
            throw new RefundException('Alipay: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 