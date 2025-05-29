<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class DpoPayGateway extends PaymentGateway
{
    // DPO Pay API URLs can vary based on the specific product/version.
    // This is a generic placeholder for their main API endpoint.
    private const API_BASE_URL_SANDBOX = 'https://secure.sandbox.dpogroup.com/api/v6/'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://secure.dpogroup.com/api/v6/'; // Example
    private const REDIRECT_URL_SANDBOX = 'https://secure.sandbox.dpogroup.com/payv2.php?ID=';
    private const REDIRECT_URL_PRODUCTION = 'https://secure.dpogroup.com/payv2.php?ID=';


    protected function getDefaultConfig(): array
    {
        return [
            'companyToken' => '',    // Your DPO Company Token
            'serviceType' => '',     // DPO Service Type ID (numeric, e.g., for specific merchants/products)
            'isSandbox' => true,
            'timeout' => 120, // DPO can sometimes be slower
            'defaultCurrency' => 'USD', // Common, but can be ZAR, KES etc.
            'defaultRedirectUrl' => 'https://example.com/dpo/return',
            'defaultBackUrl' => 'https://example.com/dpo/back', // User can click to go back
            'defaultPtl' => '5', // Payment Time Limit in minutes (optional)
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['companyToken'])) {
            throw new InvalidConfigurationException('DPO Pay: companyToken is required.');
        }
        if (empty($config['serviceType'])) {
            throw new InvalidConfigurationException('DPO Pay: serviceType is required.');
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }
    
    private function getRedirectUrl(): string
    {
         return $this->config['isSandbox'] ? self::REDIRECT_URL_SANDBOX : self::REDIRECT_URL_PRODUCTION;
    }

    // DPO Pay API requests are typically XML POSTs. JSON might be supported by newer versions/endpoints.
    // This mock will simulate an XML request structure conceptually.
    private function buildCreateTokenXml(array $data): string
    {
        $xml = new \SimpleXMLElement('<API3G/>');
        $xml->addChild('CompanyToken', $this->config['companyToken']);
        $xml->addChild('Request', 'createToken');
        $transaction = $xml->addChild('Transaction');
        $transaction->addChild('PaymentAmount', $data['amount']);
        $transaction->addChild('PaymentCurrency', $data['currency']);
        $transaction->addChild('CompanyRef', $data['orderId']);
        $transaction->addChild('RedirectURL', $data['redirectUrl']);
        $transaction->addChild('BackURL', $data['backUrl']);
        $transaction->addChild('CompanyRefUnique', '0'); // 0 = No, 1 = Yes (must be unique)
        if (isset($data['ptl'])) {
            $transaction->addChild('PTL', $data['ptl']);
        }
        // Can add customer details: customerEmail, customerFirstName, customerLastName etc.

        $services = $xml->addChild('Services');
        $service = $services->addChild('Service');
        $service->addChild('ServiceType', $this->config['serviceType']);
        $service->addChild('ServiceDescription', $data['description']);
        $service->addChild('ServiceDate', date('Y/m/d H:i')); // Format specific to DPO

        return $xml->asXML();
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('DPO Pay: Invalid or missing amount.');
        }
        $sanitizedData['currency'] = strtoupper($sanitizedData['currency'] ?? $this->config['defaultCurrency']);
        if (empty($sanitizedData['orderId'])) { // CompanyRef
            throw new InitializationException('DPO Pay: Missing orderId (CompanyRef).');
        }
        if (empty($sanitizedData['description'])) {
            throw new InitializationException('DPO Pay: Missing description (ServiceDescription).');
        }

        $requestPayload = [
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'currency' => $sanitizedData['currency'],
            'orderId' => $sanitizedData['orderId'],
            'redirectUrl' => $sanitizedData['returnUrl'] ?? $this->config['defaultRedirectUrl'],
            'backUrl' => $sanitizedData['backUrl'] ?? $this->config['defaultBackUrl'],
            'description' => $sanitizedData['description'],
            'ptl' => $sanitizedData['ptl'] ?? $this->config['defaultPtl']
        ];
        $xmlRequest = $this->buildCreateTokenXml($requestPayload);

        try {
            // $headers = ['Content-Type' => 'application/xml']; // DPO usually expects XML
            // $responseXmlString = $this->httpClient('POST', $this->getApiBaseUrl(), $xmlRequest, $headers, true);
            // $response = new \SimpleXMLElement($responseXmlString);
            // Mocked XML Response for createToken
            if ($requestPayload['amount'] == '9999.00') {
                // Simulate an error response from DPO
                $mockXml = '<API3G><Result>900</Result><ResultExplanation>Insufficient a/c balance</ResultExplanation></API3G>';
            } else {
                $mockTransToken = 'MOCK_DPO_TRANSTOKEN_' . strtoupper(uniqid());
                $mockXml = sprintf(
                    '<API3G><Result>000</Result><ResultExplanation>OK</ResultExplanation><TransToken>%s</TransToken><TransRef>MOCK_DPO_TRANSREF_%s</TransRef></API3G>',
                    $mockTransToken,
                    strtoupper(uniqid())
                );
            }
            $responseXml = new \SimpleXMLElement($mockXml);
            $response = ['body' => $responseXml, 'status_code' => 200]; // Assuming HTTP 200 always, result in XML

            if ($response['status_code'] !== 200 || !isset($response['body']->Result) || (string)$response['body']->Result !== '000') {
                $errorMsg = 'Unknown API error';
                if (isset($response['body']->ResultExplanation)) {
                    $errorMsg = (string)$response['body']->ResultExplanation;
                }
                throw new InitializationException('DPO Pay: Failed to create transaction token. Error: ' . $errorMsg . ' (Code: ' . ($response['body']->Result ?? '') . ')');
            }

            $transToken = (string)$response['body']->TransToken;
            $paymentUrl = $this->getRedirectUrl() . $transToken;

            return [
                'status' => 'pending_user_action',
                'message' => 'DPO Pay transaction token created. Redirect user to payment page.',
                'paymentUrl' => $paymentUrl,
                'transToken' => $transToken,
                'transRef' => (string)($response['body']->TransRef ?? null), // DPO's internal reference
                'orderId' => $sanitizedData['orderId'],
                'gatewayReferenceId' => $transToken, // Use TransToken for subsequent actions until TransRef confirmed
                'rawData' => json_decode(json_encode($response['body']), true) // Convert SimpleXML to array
            ];
        } catch (\Exception $e) {
            if ($e instanceof InitializationException) throw $e;
            throw new InitializationException('DPO Pay: Transaction token creation failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // DPO Pay typically uses a POST to your RedirectURL (from initialize) with transaction details.
        // It might also have a separate PUSH/notification URL mechanism (PTN - Payment Transaction Notification).
        // This mock assumes $data comes from the redirect, containing TransID, CCDapproval etc.
        // Or, if it's a PTN, it would be an XML payload to a pre-configured URL.
        $sanitizedData = $this->sanitize($data); // These are query params or POST data from redirect/PTN

        // Key parameters usually returned: TransID (your CompanyRef), PNRID (DPO internal), CCDapproval (card approval code)
        // Also verify `TransactionToken` if it's passed back.
        $companyRef = $sanitizedData['TransID'] ?? null;
        $dpoTransRef = $sanitizedData['PNRID'] ?? null; // DPO's unique transaction reference
        $transToken = $sanitizedData['TransactionToken'] ?? null;
        $ccdApproval = $sanitizedData['CCDapproval'] ?? null;
        $fraudAlert = $sanitizedData['fraudAlert'] ?? '0'; // 0 = no fraud, 1 = fraud suspected
        $statusCode = $sanitizedData['statusCode'] ?? null; // Sometimes DPO returns a status code like '000' for success.

        // For this mock, we will assume success if CCDapproval is present and non-empty, or if a known success statusCode is present.
        // A more robust check would involve a server-to-server verification (`verifyToken` or `verifyTransaction` API call).
        
        $finalStatus = 'failed';
        $message = 'DPO Pay payment processed.';

        if (!empty($dpoTransRef) && ($fraudAlert === '0' || $fraudAlert === 0)) {
            if(!empty($ccdApproval)){
                $finalStatus = 'success';
                $message .= ' Card approval received: ' . $ccdApproval;
            } elseif ($statusCode === '000' || $statusCode === '00') { // Assuming '000' or '00' means success
                $finalStatus = 'success';
                $message .= ' Status code indicates success.';
            } elseif ($statusCode === '001' || $statusCode === '002') { // Pending codes (examples)
                 $finalStatus = 'pending';
                 $message .= ' Status code indicates pending.';
            } else {
                $message .= ' No definitive success indicator found in callback/redirect. Verify transaction.';
            }
        } else {
            $message .= ' DPO Transaction Reference (PNRID) missing or fraud alert triggered. PNRID: ' . $dpoTransRef . ', Fraud: ' . $fraudAlert;
        }
        
        if ($sanitizedData['custom_force_fail'] ?? false) { $finalStatus = 'failed'; $message = 'Forced failure by custom param.';}

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $dpoTransRef, // DPO PNRID is the key transaction ID
            'orderId' => $companyRef,      // Your CompanyRef
            'gatewayReferenceId' => $transToken, // Original transaction token
            'paymentStatus' => $ccdApproval ?? $statusCode ?? 'N/A',
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // DPO Pay `verifyToken` or `verifyTransaction` API call.
        // Requires CompanyToken and TransactionToken (from initialize) or TransRef/PNRID (from process).
        $sanitizedData = $this->sanitize($data);
        $companyToken = $this->config['companyToken'];
        $transactionToken = $sanitizedData['transToken'] ?? ($sanitizedData['gatewayReferenceId'] ?? null);
        // Or verify by DPO PNRID (transactionId) if known
        $dpoPnrId = $sanitizedData['transactionId'] ?? null;

        if (empty($transactionToken) && empty($dpoPnrId)) {
            throw new VerificationException('DPO Pay: TransactionToken or transactionId (DPO PNRID) is required for verification.');
        }
        
        $xmlRequest = new \SimpleXMLElement('<API3G/>');
        $xmlRequest->addChild('CompanyToken', $companyToken);
        $xmlRequest->addChild('Request', 'verifyToken'); // or verifyTransaction if using PNRID
        if($dpoPnrId && !$transactionToken) { // Prefer verifyTransaction if PNRID is primary identifier passed
            $xmlRequest->Request = 'verifyTransaction'; 
            $xmlRequest->addChild('TransactionRef', $dpoPnrId);
        } else {
             $xmlRequest->addChild('TransactionToken', $transactionToken);
        }
        $xmlRequestString = $xmlRequest->asXML();

        try {
            // $headers = ['Content-Type' => 'application/xml'];
            // $responseXmlString = $this->httpClient('POST', $this->getApiBaseUrl(), $xmlRequestString, $headers, true);
            // $response = new \SimpleXMLElement($responseXmlString);
            // Mocked Response for verifyToken/verifyTransaction
            $mockXml = '<API3G><Result>904</Result><ResultExplanation>Transaction Not Found</ResultExplanation></API3G>'; // Default to not found
            if ($transactionToken === 'MOCK_DPO_TRANSTOKEN_SUCCESS' || $dpoPnrId === 'MOCK_DPO_TRANSREF_SUCCESS') {
                $mockXml = '<API3G><Result>000</Result><ResultExplanation>Transaction Paid</ResultExplanation><FraudAlert>0</FraudAlert><FraudExplaInation>Pass</FraudExplaInation><PNRREF>PNR_SUCCESS_VERIFY</PNRREF><AccRef>ORDER_VERIFY_SUCCESS</AccRef><CustomerName>Test User</CustomerName></API3G>';
            } elseif ($transactionToken === 'MOCK_DPO_TRANSTOKEN_PENDING' || $dpoPnrId === 'MOCK_DPO_TRANSREF_PENDING') {
                $mockXml = '<API3G><Result>001</Result><ResultExplanation>Transaction Still Pending</ResultExplanation><FraudAlert>0</FraudAlert></API3G>';
            } elseif ($transactionToken === 'MOCK_DPO_TRANSTOKEN_FRAUD' || $dpoPnrId === 'MOCK_DPO_TRANSREF_FRAUD'){
                $mockXml = '<API3G><Result>000</Result><ResultExplanation>Transaction Paid</ResultExplanation><FraudAlert>1</FraudAlert><FraudExplaInation>Suspected Fraud</FraudExplaInation></API3G>';
            }

            $responseXml = new \SimpleXMLElement($mockXml);
            $response = ['body' => $responseXml, 'status_code' => 200];

            $resultCode = (string)($response['body']->Result ?? '999');
            $resultExplanation = (string)($response['body']->ResultExplanation ?? 'Unknown error');
            $fraudAlert = (string)($response['body']->FraudAlert ?? '0');
            $dpoTransactionRef = (string)($response['body']->PNRREF ?? ($response['body']->TransRef ?? $dpoPnrId));
            $companyRef = (string)($response['body']->AccRef ?? ($sanitizedData['orderId'] ?? null));

            $finalStatus = 'failed';
            if ($resultCode === '000' && $fraudAlert === '0') {
                $finalStatus = 'success';
            } elseif (in_array($resultCode, ['001', '002', '901' /*Awaiting PNR*/, '903' /*Awaiting Payment*/])) { // Example pending codes
                $finalStatus = 'pending';
            } // Other codes (e.g. 900, 902, 904, or 000 with fraudAlert=1) are failures
            
            if ($fraudAlert !== '0') $finalStatus = 'failed'; // Override if fraud

            return [
                'status' => $finalStatus,
                'message' => 'DPO Pay verification: ' . $resultExplanation . ' (Result: ' . $resultCode . ', Fraud: ' . $fraudAlert . ')',
                'transactionId' => $dpoTransactionRef,
                'orderId' => $companyRef,
                'paymentStatus' => $resultCode,
                'rawData' => json_decode(json_encode($response['body']), true)
            ];
        } catch (\Exception $e) {
            throw new VerificationException('DPO Pay: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // DPO Pay refunds are typically done via `refundTransaction` API call using PNRID/TransRef.
        // This requires specific permissions and setup.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // DPO Transaction Reference (PNRID/TransRef)
            throw new RefundException('DPO Pay: transactionId (DPO PNRID/TransRef) is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('DPO Pay: Invalid or missing amount for refund.');
        }

        $xml = new \SimpleXMLElement('<API3G/>');
        $xml->addChild('CompanyToken', $this->config['companyToken']);
        $xml->addChild('Request', 'refundTransaction');
        $transaction = $xml->addChild('Transaction');
        $transaction->addChild('TransactionRef', $sanitizedData['transactionId']);
        $transaction->addChild('RefundAmount', number_format((float)$sanitizedData['amount'], 2, '.', ''));
        $transaction->addChild('RefundCurrency', strtoupper($sanitizedData['currency'] ?? $this->config['defaultCurrency']));
        $transaction->addChild('RefundDetails', $sanitizedData['reason'] ?? 'Merchant initiated refund');
        // $transaction->addChild('CompanyRef', $sanitizedData['refundId'] ?? 'REF_'.uniqid()); // Your ref for the refund
        $xmlRequestString = $xml->asXML();

        try {
            // $headers = ['Content-Type' => 'application/xml'];
            // $responseXmlString = $this->httpClient('POST', $this->getApiBaseUrl(), $xmlRequestString, $headers, true);
            // $response = new \SimpleXMLElement($responseXmlString);
            // Mocked Response for refundTransaction
            $mockXml = '<API3G><Result>902</Result><ResultExplanation>Original Transaction not found</ResultExplanation></API3G>';
            if ($sanitizedData['transactionId'] === 'MOCK_DPO_TRANSREF_REFUNDABLE') {
                if ((float)$sanitizedData['amount'] == 99.99) {
                     $mockXml = '<API3G><Result>801</Result><ResultExplanation>Refund amount exceeds original transaction</ResultExplanation></API3G>';
                } else {
                     $mockXml = '<API3G><Result>000</Result><ResultExplanation>Refund successful</ResultExplanation><TransactionRef>'.($sanitizedData['transactionId']).'_REF</TransactionRef></API3G>';
                }
            }
            $responseXml = new \SimpleXMLElement($mockXml);
            $response = ['body' => $responseXml, 'status_code' => 200];

            if ($response['status_code'] !== 200 || (string)($response['body']->Result ?? '999') !== '000') {
                throw new RefundException('DPO Pay: Refund API call failed. Error: ' . ((string)$response['body']->ResultExplanation ?? 'Unknown API error') . ' (Code: ' . ((string)$response['body']->Result ?? '') . ')');
            }

            return [
                'status' => 'success', // DPO refunds are often synchronous if Result is 000
                'message' => 'DPO Pay refund successful. ' . (string)$response['body']->ResultExplanation,
                'refundId' => (string)($response['body']->TransactionRef ?? ($sanitizedData['transactionId'] . '_REF')), // New ref for refund if provided
                'gatewayReferenceId' => $sanitizedData['transactionId'], // Original DPO TransRef
                'paymentStatus' => 'REFUNDED',
                'rawData' => json_decode(json_encode($response['body']), true)
            ];
        } catch (\Exception $e) {
            if ($e instanceof RefundException) throw $e;
            throw new RefundException('DPO Pay: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 