<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class WeChatPayGateway extends PaymentGateway
{
    // WeChat Pay API v2 (legacy) and v3 URLs. This mock will conceptually lean towards v3 patterns.
    private const API_BASE_URL_V3_SANDBOX = 'https://api.mch.weixin.qq.com/v3'; // v3 doesn't have a true sandbox, but test mode via config
    private const API_BASE_URL_V3_PRODUCTION = 'https://api.mch.weixin.qq.com/v3';
    // For older v2 XML based API:
    // private const API_BASE_URL_V2 = 'https://api.mch.weixin.qq.com';

    protected function getDefaultConfig(): array
    {
        return [
            'app_id' => '',             // Your AppID (Official Account, Mini Program, or Mobile App)
            'mch_id' => '',             // Your Merchant ID
            'api_key_v2' => '',         // API Key for v2 (MD5/HMAC-SHA256 signing)
            'api_v3_key' => '',         // APIv3 Key (for AES-GCM decryption of callbacks)
            'merchant_serial_no' => '', // Your Merchant API Certificate Serial Number (for v3 requests)
            'merchant_private_key_path' => '', // Path to your Merchant Private Key .pem file (for v3 requests)
            'wechatpay_platform_certificate_path' => '', // Path to store/read WeChat Pay Platform Certificate .pem (for v3 response verification)
            'isSandbox' => false,        // v3 uses live URL, sandbox mode is via API parameters or specific sandbox endpoints for v2
            'v2_sandbox_key_endpoint' => 'https://api.mch.weixin.qq.com/sandboxnew/pay/getsignkey',
            'timeout' => 60,
            'notify_url' => 'https://example.com/wechatpay/notify',
            'default_trade_type' => 'JSAPI', // JSAPI, NATIVE, APP, H5, MWEB
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['app_id'])) {
            throw new InvalidConfigurationException('WeChat Pay: app_id is required.');
        }
        if (empty($config['mch_id'])) {
            throw new InvalidConfigurationException('WeChat Pay: mch_id is required.');
        }
        // Depending on API version target (v2 vs v3), different keys are critical
        // For v3:
        if (empty($config['api_v3_key'])) {
            // throw new InvalidConfigurationException('WeChat Pay (v3): api_v3_key is required.');
        }
        if (empty($config['merchant_serial_no'])) {
            // throw new InvalidConfigurationException('WeChat Pay (v3): merchant_serial_no is required.');
        }
        if (empty($config['merchant_private_key_path'])) {
            // throw new InvalidConfigurationException('WeChat Pay (v3): merchant_private_key_path is required.');
        }
        // For v2:
        // if (empty($config['api_key_v2'])) {
        // throw new InvalidConfigurationException('WeChat Pay (v2): api_key_v2 is required.');
        // }
    }

    private function getApiBaseUrl(): string
    {
        // This mock will primarily use v3 endpoints conceptually
        return $this->config['isSandbox'] ? self::API_BASE_URL_V3_SANDBOX : self::API_BASE_URL_V3_PRODUCTION;
    }

    // Conceptual v3 Signature Generation (complex, involves private key, canonical request string)
    private function generateV3Signature(string $method, string $urlPath, string $timestamp, string $nonce, string $body = ''): string
    {
        // Actual implementation uses RSA SHA256 with merchant private key
        // Canonical string: HTTPMethod + URLPathWithQuery + Timestamp + Nonce + Body + \n
        // Simplified Mock:
        if ($body === 'SIMULATE_V3_SIGN_FAIL') return 'FAIL_V3_SIGNATURE';
        return 'MOCK_WECHATV3_SIGNATURE_FOR_' . md5($method . $urlPath . $timestamp . $nonce . $body . $this->config['merchant_serial_no']);
    }

    // Conceptual v3 Signature Verification (complex, involves platform certificate)
    private function verifyV3Signature(array $headers, string $body): bool
    {
        // Check headers: Wechatpay-Timestamp, Wechatpay-Nonce, Wechatpay-Signature, Wechatpay-Serial
        // Verify using the platform certificate corresponding to Wechatpay-Serial
        if (($headers['Wechatpay-Signature'] ?? '') === 'FAIL_V3_CALLBACK_SIGNATURE') return false;
        // Simplified mock
        return true;
    }
    
    // Conceptual v2 (XML) Signature Generation
    private function generateV2Signature(array $params): string
    {
        // 1. Filter out empty values and 'sign' key
        // 2. Sort alphabetically by key
        // 3. Append api_key_v2: stringA&key=YOUR_API_KEY_V2
        // 4. MD5 or HMAC-SHA256 encode, then uppercase
        // Simplified Mock:
        if (isset($params['total_fee']) && $params['total_fee'] == 999998) return 'FAIL_V2_SIGNATURE';
        return strtoupper(md5(http_build_query($params) . '&key=' . $this->config['api_key_v2']));
    }

    protected function arrayToXml(array $arr): string
    {
        $xml = '<xml>';
        foreach ($arr as $key => $val) {
            if (is_numeric($val)) {
                $xml .= '<' . $key . '>' . $val . '</' . $key . '>';
            } else {
                $xml .= '<' . $key . '><![CDATA[' . $val . ']]></' . $key . '>';
            }
        }
        $xml .= '</xml>';
        return $xml;
    }

    protected function xmlToArray(string $xml): array
    {
        // Disable external entity loading to prevent XXE
        libxml_disable_entity_loader(true);
        $values = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        return $values;
    }


    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        $tradeType = $sanitizedData['trade_type'] ?? $this->config['default_trade_type'];

        if (empty($sanitizedData['orderId'])) { // out_trade_no
            throw new InitializationException('WeChat Pay: Missing orderId (out_trade_no).');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('WeChat Pay: Invalid amount. Amount should be in lowest currency unit (e.g., fen).');
        }
        if (empty($sanitizedData['description'])) { // body
            throw new InitializationException('WeChat Pay: Missing description (body).');
        }

        // This example leans towards v3 JSAPI/Native payment flow conceptually
        // For v3, amounts are in fen, description is `description` field.
        $v3Payload = [
            'appid' => $this->config['app_id'],
            'mchid' => $this->config['mch_id'],
            'description' => $sanitizedData['description'],
            'out_trade_no' => $sanitizedData['orderId'],
            'notify_url' => $this->config['notify_url'],
            'amount' => [
                'total' => (int)round($sanitizedData['amount']), // Amount in fen
                'currency' => $sanitizedData['currency'] ?? 'CNY',
            ],
        ];

        $endpointPath = '';
        switch ($tradeType) {
            case 'JSAPI':
                $endpointPath = '/pay/transactions/jsapi';
                $v3Payload['payer'] = ['openid' => $sanitizedData['openid'] ?? 'MOCK_OPENID_REQUIRED_FOR_JSAPI'];
                if (empty($v3Payload['payer']['openid'])) {
                    throw new InitializationException('WeChat Pay JSAPI: openid is required.');
                }
                break;
            case 'NATIVE':
                $endpointPath = '/pay/transactions/native';
                break;
            case 'APP':
                $endpointPath = '/pay/transactions/app';
                break;
            case 'H5': // MWEB in v2 parlance
                $endpointPath = '/pay/transactions/h5';
                $v3Payload['scene_info'] = [
                    'payer_client_ip' => $sanitizedData['payer_client_ip'] ?? '127.0.0.1',
                    'h5_info' => ['type' => $sanitizedData['h5_type'] ?? 'Wap'] // e.g. Wap, IOS, Android
                ];
                break;
            default:
                throw new InitializationException("WeChat Pay: Unsupported trade_type '{$tradeType}'.");
        }

        try {
            // Mocking v3 API call
            $timestamp = (string)time();
            $nonce = uniqid('wx');
            $bodyJson = json_encode($v3Payload);
            // $signature = $this->generateV3Signature('POST', $endpointPath, $timestamp, $nonce, $bodyJson);
            // $authHeader = sprintf('WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"',
            // $this->config['mch_id'], $nonce, $signature, $timestamp, $this->config['merchant_serial_no']
            // );
            // $headers = ['Authorization' => $authHeader, 'Content-Type' => 'application/json', 'Accept' => 'application/json'];
            // $responseJson = $this->httpClient('POST', $this->getApiBaseUrl() . $endpointPath, $bodyJson, $headers);
            // $response = json_decode($responseJson, true);

            // Mocked Response from WeChat Pay v3 API
            if ($v3Payload['amount']['total'] == 999999) { // Simulate API rejection
                throw new InitializationException('WeChat Pay: API rejected request (simulated amount error).');
            }
            
            $mockResponse = [];
            if ($tradeType === 'NATIVE') {
                $mockResponse['code_url'] = 'weixin://wxpay/bizpayurl?pr=MOCK_QR_CODE_FOR_' . $sanitizedData['orderId'];
            } elseif ($tradeType === 'JSAPI' || $tradeType === 'APP') {
                // JSAPI and APP typically return a prepay_id to be used with SDK to evoke payment
                $mockResponse['prepay_id'] = 'wx_prepay_id_MOCK_' . $timestamp . uniqid();
            } elseif ($tradeType === 'H5') {
                $mockResponse['h5_url'] = 'https://wx.tenpay.com/cgi-bin/mmpayweb-bin/checkmweb?prepay_id=MOCK_H5_PREPAY&package=VALUE#wechat_redirect';
            }

            if (empty($mockResponse)) {
                throw new InitializationException('WeChat Pay: Failed to get necessary parameter (e.g. prepay_id or code_url) from simulated API.');
            }
            
            // Constructing return data based on trade type
            $returnData = [
                'orderId' => $sanitizedData['orderId'],
                'gatewayReferenceId' => $mockResponse['prepay_id'] ?? null, // Prepay ID is a key reference
                'rawData' => array_merge($v3Payload, $mockResponse) // Combine request payload with mock response fields
            ];

            if ($tradeType === 'NATIVE') {
                $returnData['status'] = 'pending_user_action'; // User needs to scan QR code
                $returnData['message'] = 'WeChat Pay QR code URL generated. User needs to scan.';
                $returnData['qrCodeUrl'] = $mockResponse['code_url'];
            } elseif ($tradeType === 'JSAPI') {
                // For JSAPI, you need to generate parameters for the JS SDK (timeStamp, nonceStr, package, signType, paySign)
                $jsapiParams = [
                    'appId' => $this->config['app_id'],
                    'timeStamp' => (string)time(),
                    'nonceStr' => uniqid('wx'),
                    'package' => 'prepay_id=' . $mockResponse['prepay_id'],
                    'signType' => 'RSA', // Or MD5 for older versions, but v3 uses RSA for its own layer.
                                        // The JS parameters might still use MD5 or SHA256 based on WeixinJSBridge requirements.
                                        // This part is complex and depends on specific frontend SDK version.
                ];
                // $jsapiParams['paySign'] = $this->generateV2Signature($jsapiParams); // Conceptual sign for JS parameters
                $jsapiParams['paySign'] = 'MOCK_JSAPI_PAYSIGN_FOR_'.md5(http_build_query($jsapiParams));

                $returnData['status'] = 'pending_client_sdk_action';
                $returnData['message'] = 'WeChat Pay JSAPI initialized. Pass parameters to WeixinJSBridge.';
                $returnData['jsapiParams'] = $jsapiParams;
            } elseif ($tradeType === 'APP') {
                 // For APP, similar to JSAPI, parameters for SDK are generated using prepay_id
                 $appParams = [
                    'appid' => $this->config['app_id'],
                    'partnerid' => $this->config['mch_id'],
                    'prepayid' => $mockResponse['prepay_id'],
                    'package' => 'Sign=WXPay', // Fixed value
                    'noncestr' => uniqid('wx'),
                    'timestamp' => (string)time(),
                ];
                // $appParams['sign'] = $this->generateV2Signature($appParams); // Conceptual sign for APP parameters
                $appParams['sign'] = 'MOCK_APP_PAYSIGN_FOR_'.md5(http_build_query($appParams));
                
                $returnData['status'] = 'pending_client_sdk_action';
                $returnData['message'] = 'WeChat Pay APP initialized. Pass parameters to client SDK.';
                $returnData['appParams'] = $appParams;
            } elseif ($tradeType === 'H5') {
                 $returnData['status'] = 'pending_user_redirect';
                 $returnData['message'] = 'WeChat Pay H5 payment initialized. Redirect user to h5_url.';
                 $returnData['paymentUrl'] = $mockResponse['h5_url'];
            }
            return $returnData;

        } catch (\Exception $e) {
            if ($e instanceof InitializationException) throw $e;
            throw new InitializationException('WeChat Pay: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Processes asynchronous notification (XML for v2, JSON for v3)
        // This mock assumes v3 JSON callback structure with AES-GCM encryption.
        $sanitizedData = $this->sanitize($data); // This is the raw callback body (JSON string)
        
        // For v3, headers are critical: Wechatpay-Timestamp, Wechatpay-Nonce, Wechatpay-Signature, Wechatpay-Serial
        // $headers = []; // Populate from actual request headers
        // if (!$this->verifyV3Signature($headers, $rawBodyStringFromRequest)) {
        //     throw new ProcessingException('WeChat Pay Callback (v3): Signature verification failed.');
        // }

        // The actual payload in v3 callback is in `resource.ciphertext` and needs decryption using AES-GCM with api_v3_key.
        // $encryptedData = $sanitizedData['resource']['ciphertext'] ?? '';
        // $associatedData = $sanitizedData['resource']['associated_data'] ?? '';
        // $nonce = $sanitizedData['resource']['nonce'] ?? '';
        // $decryptedPayloadJson = aes_256_gcm_decrypt($encryptedData, $this->config['api_v3_key'], $nonce, $associatedData);
        // $payload = json_decode($decryptedPayloadJson, true);
        // Mocking decrypted payload for simplicity. Assume $data is already the decrypted payload.
        $payload = $sanitizedData; 

        if (empty($payload['out_trade_no']) || empty($payload['transaction_id']) || empty($payload['trade_state'])) {
            throw new ProcessingException('WeChat Pay Callback (v3): Invalid decrypted payload. Missing critical fields.');
        }

        $orderId = $payload['out_trade_no'];
        $wechatTransactionId = $payload['transaction_id'];
        $tradeState = $payload['trade_state']; // SUCCESS, REFUND, NOTPAY, CLOSED, REVOKED, USERPAYING, PAYERROR
        $tradeStateDesc = $payload['trade_state_desc'] ?? '';

        $finalStatus = 'failed';
        $message = 'WeChat Pay payment status: ' . $tradeState . ' (' . $tradeStateDesc . ')';

        if ($tradeState === 'SUCCESS') {
            $finalStatus = 'success';
        } elseif ($tradeState === 'USERPAYING') {
            $finalStatus = 'pending';
        } elseif (in_array($tradeState, ['REFUND', 'CLOSED', 'REVOKED', 'PAYERROR', 'NOTPAY'])){
            $finalStatus = 'failed'; // Or more specific e.g. 'refunded', 'cancelled'
            if ($tradeState === 'REFUND') $finalStatus = 'refunded';
        }
        
        // For v3 notifications, respond with JSON: {"code": "SUCCESS"/"FAIL", "message": "Optional error message"}

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $wechatTransactionId,
            'orderId' => $orderId,
            'paymentStatus' => $tradeState,
            'amount' => $payload['amount']['total'] ?? ($payload['amount']['payer_total'] ?? null), // Amount in fen
            'rawData' => $payload
        ];
    }

    public function verify(array $data): array
    {
        // Query order API (v3: /pay/transactions/out-trade-no/{out_trade_no} or /id/{transaction_id})
        $sanitizedData = $this->sanitize($data);
        $outTradeNo = $sanitizedData['orderId'] ?? null;
        $transactionId = $sanitizedData['transactionId'] ?? null;

        if (empty($outTradeNo) && empty($transactionId)) {
            throw new VerificationException('WeChat Pay: orderId (out_trade_no) or transactionId is required for query.');
        }

        $endpointPath = '';
        if ($transactionId) {
            $endpointPath = '/pay/transactions/id/' . $transactionId . '?mchid=' . $this->config['mch_id'];
        } else {
            $endpointPath = '/pay/transactions/out-trade-no/' . $outTradeNo . '?mchid=' . $this->config['mch_id'];
        }

        try {
            // Mocking v3 API query call
            // $timestamp = (string)time(); $nonce = uniqid('wx');
            // $signature = $this->generateV3Signature('GET', $endpointPath, $timestamp, $nonce);
            // Construct Auth header...
            // $responseJson = $this->httpClient('GET', $this->getApiBaseUrl() . $endpointPath, [], $headers);
            // $response = json_decode($responseJson, true);
            // Mocked Response:
            $mockResponse = null;
            $queryKey = $transactionId ?? $outTradeNo;

            if ($queryKey === 'WX_TXN_FAILQUERY' || $queryKey === 'ORDER_FAILQUERY'){
                throw new VerificationException('WeChat Pay Query: API error (simulated).');
            }

            if ($queryKey === 'WX_TXN_SUCCESS' || $queryKey === 'ORDER_SUCCESS') {
                $mockResponse = ['trade_state' => 'SUCCESS', 'trade_state_desc' => 'Payment successful', 'transaction_id' => 'WXS avión SUCCESS_TID', 'out_trade_no' => 'ORDER_SUCCESS_OID', 'amount' => ['total' => 1000]];
            } elseif ($queryKey === 'WX_TXN_USERPAYING' || $queryKey === 'ORDER_USERPAYING') {
                $mockResponse = ['trade_state' => 'USERPAYING', 'trade_state_desc' => 'User paying', 'transaction_id' => 'WXS_PEND_TID', 'out_trade_no' => 'ORDER_PEND_OID', 'amount' => ['total' => 500]];
            } elseif ($queryKey === 'WX_TXN_CLOSED' || $queryKey === 'ORDER_CLOSED') {
                $mockResponse = ['trade_state' => 'CLOSED', 'trade_state_desc' => 'Order closed', 'transaction_id' => 'WXS_CLOSED_TID', 'out_trade_no' => 'ORDER_CLOSED_OID', 'amount' => ['total' => 200]];
            } else { // Not Found
                $mockResponse = ['code' => 'RESOURCE_NOT_EXISTS', 'message' => 'The requested resource does not exist.'];
            }
            $response = $mockResponse;
            // End Mock
            
            if (isset($response['code']) && $response['code'] === 'RESOURCE_NOT_EXISTS'){
                 throw new VerificationException('WeChat Pay Query: Transaction not found. ' . $response['message']);
            }
            if (empty($response['trade_state'])){
                throw new VerificationException('WeChat Pay Query: Invalid response from API.');
            }

            $tradeState = $response['trade_state'];
            $finalStatus = 'failed';
            if ($tradeState === 'SUCCESS') $finalStatus = 'success';
            elseif ($tradeState === 'USERPAYING') $finalStatus = 'pending';

            return [
                'status' => $finalStatus,
                'message' => 'WeChat Pay Query Status: ' . ($response['trade_state_desc'] ?? $tradeState),
                'transactionId' => $response['transaction_id'] ?? null,
                'orderId' => $response['out_trade_no'] ?? null,
                'paymentStatus' => $tradeState,
                'amount' => $response['amount']['total'] ?? null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new VerificationException('WeChat Pay: Transaction query failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // v3 Refund API: /v3/refund/domestic/refunds
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('WeChat Pay: Invalid refund amount.');
        }
        // Must specify either transaction_id (WeChat's) or out_trade_no (yours)
        if (empty($sanitizedData['transactionId']) && empty($sanitizedData['orderId'])) {
            throw new RefundException('WeChat Pay: transactionId or orderId required for refund.');
        }

        $payload = [
            // 'sub_mchid' => '...', // If operating as service provider for sub-merchant
            'out_refund_no' => $sanitizedData['refundId'] ?? ('WXREF_' . uniqid()), // Your unique refund ID
            'reason' => $sanitizedData['reason'] ?? 'Merchant refund',
            'notify_url' => $this->config['refund_notify_url'] ?? ($this->config['notify_url'] . '_refund'), // Specific refund notify URL
            'amount' => [
                'refund' => (int)round($sanitizedData['amount']), // Refund amount in fen
                'total' => (int)round($sanitizedData['originalAmount']), // Original order total amount in fen
                'currency' => $sanitizedData['currency'] ?? 'CNY',
            ],
        ];
        if (!empty($sanitizedData['transactionId'])) {
            $payload['transaction_id'] = $sanitizedData['transactionId'];
        } else {
            $payload['out_trade_no'] = $sanitizedData['orderId'];
        }
        if(empty($payload['amount']['total'])){
            throw new RefundException('WeChat Pay: originalAmount is required in refund data.');
        }

        try {
            // Mocking v3 Refund API call
            // $timestamp = time(); $nonce = uniqid(); $bodyJson = json_encode($payload);
            // $signature = $this->generateV3Signature('POST', '/refund/domestic/refunds', $timestamp, $nonce, $bodyJson);
            // ... construct auth header and make httpClient call ...
            // $response = json_decode($responseJson, true);
            // Mocked Response:
            $mockResponse = null;
            if ($payload['amount']['refund'] == 99998) { // Simulate error
                $mockResponse = ['code' => 'PARAM_ERROR', 'message' => 'Invalid refund amount (simulated).'];
            } elseif (($payload['transaction_id'] ?? $payload['out_trade_no']) === 'WX_TXN_NO_REFUND') {
                $mockResponse = ['code' => 'USER_ACCOUNT_ABNORMAL', 'message' => 'Transaction not eligible for refund (simulated).'];
            } else {
                $mockResponse = [
                    'refund_id' => 'WX_REFUNDID_MOCK_' . uniqid(), // WeChat Pay's refund ID
                    'out_refund_no' => $payload['out_refund_no'],
                    'transaction_id' => $payload['transaction_id'] ?? ('WX_TXN_FOR_REFUND_' . $payload['out_trade_no']),
                    'out_trade_no' => $payload['out_trade_no'] ?? ('ORDER_FOR_REFUND_' . $payload['transaction_id']),
                    'channel' => 'ORIGINAL', // Refund channel
                    'status' => 'PROCESSING', // Or SUCCESS, CLOSED, ABNORMAL
                    'amount' => $payload['amount'],
                    'create_time' => date(DATE_ISO8601),
                ];
            }
            $response = $mockResponse;
            // End Mock

            if (isset($response['code']) && !in_array($response['status'] ?? '', ['SUCCESS', 'PROCESSING'])) { // SUCCESS/PROCESSING for refund status is ok initially
                throw new RefundException('WeChat Pay Refund: API call failed. ' . ($response['message'] ?? ($response['code'] ?? 'Unknown error')));
            }

            $refundStatus = $response['status'] ?? 'failed'; // PROCESSING, SUCCESS, CLOSED, ABNORMAL
            $finalStatus = 'pending'; // Default to pending as refunds are often async
            if ($refundStatus === 'SUCCESS') $finalStatus = 'success';
            elseif ($refundStatus === 'CLOSED' || $refundStatus === 'ABNORMAL') $finalStatus = 'failed';
            
            return [
                'status' => $finalStatus,
                'message' => 'WeChat Pay Refund Status: ' . $refundStatus . '. ' . ($response['message'] ?? ''),
                'refundId' => $response['refund_id'] ?? $response['out_refund_no'], // WeChat's refund_id or your out_refund_no
                'gatewayReferenceId' => $response['transaction_id'] ?? null, // Original WeChat transaction ID
                'orderId' => $response['out_trade_no'] ?? null,
                'paymentStatus' => 'REFUND_' . strtoupper($refundStatus),
                'amount' => $response['amount']['refund'] ?? null, // Amount in fen
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            throw new RefundException('WeChat Pay: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 