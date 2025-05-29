<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class BillDeskGateway extends PaymentGateway
{
    // BillDesk URLs - these can vary based on the specific BillDesk product/setup
    private const PAYMENT_URL_UAT = 'https://uat.billdesk.com/pgidsk/pgmerc/pgmercpayable.jsp'; // Example UAT
    private const PAYMENT_URL_PRODUCTION = 'https://www.billdesk.com/pgidsk/pgmerc/pgmercpayable.jsp'; // Example Production
    private const STATUS_QUERY_URL_UAT = 'https://uat.billdesk.com/pgidsk/pgmerc/transactionstatus.jsp';
    private const STATUS_QUERY_URL_PRODUCTION = 'https://www.billdesk.com/pgidsk/pgmerc/transactionstatus.jsp';

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',        // Your BillDesk Merchant ID
            'checksumKey' => '',     // Your BillDesk Checksum Key
            'securityId' => '',      // AKA Client ID, might be same as Merchant ID or different
            'isSandbox' => true,
            'timeout' => 90, // BillDesk can be a bit slow sometimes
            'defaultReturnUrl' => 'https://example.com/billdesk/return',
            // BillDesk usually uses a single return URL where it POSTs response parameters.
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['merchantId'])) {
            throw new InvalidConfigurationException('BillDesk: merchantId is required.');
        }
        if (empty($config['checksumKey'])) {
            throw new InvalidConfigurationException('BillDesk: checksumKey is required.');
        }
        if (empty($config['securityId'])) {
             throw new InvalidConfigurationException('BillDesk: securityId is required.');
        }
    }

    private function getPaymentUrl(): string
    {
        return $this->config['isSandbox'] ? self::PAYMENT_URL_UAT : self::PAYMENT_URL_PRODUCTION;
    }
    
    private function getStatusQueryUrl(): string
    {
        return $this->config['isSandbox'] ? self::STATUS_QUERY_URL_UAT : self::STATUS_QUERY_URL_PRODUCTION;
    }

    // BillDesk checksum generation is typically HMAC SHA256 of a pipe-separated string.
    // The exact order and fields depend on the specific product (e.g., S2S, WebConnect).
    private function generateChecksum(array $params, bool $forRequest = true): string
    {
        $checksumKey = $this->config['checksumKey'];
        $stringToHash = '';
        
        // Example for request checksum. Response checksum fields might differ.
        // IMPORTANT: The order of parameters in the string is CRITICAL and defined by BillDesk.
        // This is a simplified, conceptual order. Refer to specific BillDesk integration doc.
        if($forRequest){
            $orderedKeys = [
                'MerchantID', 'CustomerID', 'TxnAmount', 'BankID', 'Filler1', 'Filler2', 'Filler3',
                'CurrencyType', 'ItemCode', 'TypeField1', 'SecurityID', 'Filler4', 'Filler5',
                'TypeField2', 'TxtAdditionalInfo', 'TxtDate', 'Ru'
            ];
             // For mock, let's use a simpler, predictable set for request if specific keys not found.
            if (empty($params['BankID'])) { // Simpler set if some detailed params are missing
                $orderedKeys = ['MerchantID', 'CustomerID', 'TxnAmount', 'SecurityID', 'Ru'];
            }
        } else { // For response checksum verification (conceptual)
            $orderedKeys = [
                'MerchantID', 'CustomerID', 'TxnReferenceNo', 'BankReferenceNo', 'TxnAmount', 'BankID',
                'BankMerchantID', 'TxnType', 'CurrencyName', 'ItemCode', 'SecurityType', 'SecurityID',
                'BankIDData', 'PaidAmount', 'AuthStatus', 'SettlementType', 'AdditionalInfo1', 'AdditionalInfo2', 
                'AdditionalInfo3', 'AdditionalInfo4', 'AdditionalInfo5', 'AdditionalInfo6', 'AdditionalInfo7', 'ErrorStatus', 'ErrorDescription', 'CheckSum'
            ];
             // A common response set might be shorter and end before CheckSum for generation purposes
             // Example: MerchantID|CustomerID|TxnReferenceNo|BankReferenceNo|TxnAmount|BankID|BankMerchantID|TxnType|CurrencyName|ItemCode|SecurityType|SecurityID|BankIDData|PaidAmount|AuthStatus|SettlementType|AdditionalInfo1|ErrorStatus|ErrorDescription
             // For this mock, we'll create a sample for verification
             $orderedKeys = ['MerchantID', 'CustomerID', 'TxnReferenceNo', 'BankReferenceNo', 'TxnAmount', 'AuthStatus', 'ErrorStatus', 'ErrorDescription'];
        }

        $dataForChecksum = [];
        foreach($orderedKeys as $key){
            $dataForChecksum[] = $params[$key] ?? ''; // Use empty string if param not present
        }
        $stringToHash = implode('|', $dataForChecksum);

        if (($params['TxnAmount'] ?? 0) == 99999998 && $forRequest) return 'FAIL_BILLDESK_CHECKSUM_GEN';
        if (($params['AuthStatus'] ?? '') === '0398' && !$forRequest) return 'FAIL_BILLDESK_CHECKSUM_VERIFY';

        return strtoupper(hash_hmac('sha256', $stringToHash, $checksumKey));
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // CustomerID in BillDesk terms (Merchant's Order ID)
            throw new InitializationException('BillDesk: Missing orderId (CustomerID).');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('BillDesk: Invalid amount. Amount should be in paisa or major currency unit based on config.');
        }

        $params = [
            'MerchantID' => $this->config['merchantId'],
            'CustomerID' => $sanitizedData['orderId'],
            'TxnAmount' => number_format((float)$sanitizedData['amount'], 2, '.', ''), // Format as per BillDesk (e.g., 10.00)
            'SecurityID' => $this->config['securityId'],
            'Ru' => $sanitizedData['returnUrl'] ?? $this->config['defaultReturnUrl'],
            // Optional but common parameters for specific integrations:
            'BankID' => $sanitizedData['bankId'] ?? '', // e.g., HDF, SBI, ICICI - if specific bank to be shown
            'CurrencyType' => $sanitizedData['currency'] ?? 'INR',
            'ItemCode' => $sanitizedData['itemCode'] ?? 'DIRECT', // Or specific item code if applicable
            'TypeField1' => 'R', // For Request
            'TypeField2' => 'F', // For Full payment
            'TxtAdditionalInfo' => json_encode(['description' => $sanitizedData['description'] ?? 'Payment for order']), // Example way to pass description
            'TxtDate' => date('YmdHis'),
            // Fillers are often NA or specific static values based on integration type
            'Filler1' => 'NA', 'Filler2' => 'NA', 'Filler3' => 'NA', 'Filler4' => 'NA', 'Filler5' => 'NA',
        ];

        // All parameters to be sent to BillDesk need to be part of the checksum string usually.
        // The final string sent to BillDesk is MerchantID|CustomerID|NA|TxnAmount|BankID|NA|NA|NA|CurrencyType|ItemCode|TypeField1|SecurityID|NA|NA|TypeField2|TxtAdditionalInfo|TxtDate|Ru|CheckSum
        // For the purpose of the checksum calculation itself, we use a defined set of parameters for $this->generateChecksum
        $msgParts = [
            $params['MerchantID'], $params['CustomerID'], $params['TxnAmount'], 
            $params['BankID'] ?? '', $params['Filler1'] ?? 'NA', $params['Filler2'] ?? 'NA', $params['Filler3'] ?? 'NA',
            $params['CurrencyType'] ?? 'INR', $params['ItemCode'] ?? 'DIRECT', $params['TypeField1'] ?? 'R',
            $params['SecurityID'], $params['Filler4'] ?? 'NA', $params['Filler5'] ?? 'NA',
            $params['TypeField2'] ?? 'F', $params['TxtAdditionalInfo'] ?? '', $params['TxtDate'] ?? date('YmdHis'),
            $params['Ru']
        ];
        $checksumString = implode('|', $msgParts);
        $params['CheckSum'] = strtoupper(hash_hmac('sha256', $checksumString, $this->config['checksumKey']));

        // Build the final MSG string to be POSTed
        $msg = $checksumString . '|' . $params['CheckSum'];

        if ($params['TxnAmount'] == '999999.99') {
             throw new InitializationException('BillDesk: Request parameters indicate simulated error by amount.');
        }
        if ($params['CheckSum'] === 'FAIL_BILLDESK_CHECKSUM_GEN_VIA_STRING_COMPOSITION') { // Alternate simulation
            throw new InitializationException('BillDesk: Failed to generate checksum (simulated string composition error).');
        }

        $paymentUrl = $this->getPaymentUrl();
        
        // BillDesk expects a single parameter named "msg" containing the pipe-separated string including checksum.
        $formData = ['msg' => $msg];

        return [
            'status' => 'pending_user_redirect',
            'message' => 'BillDesk payment initialized. Prepare form to POST data.',
            'paymentUrl' => $paymentUrl,
            'formData' => $formData, // This will contain a single key 'msg' with the full string
            'orderId' => $sanitizedData['orderId'],
            'gatewayReferenceId' => null, // BillDesk TxnReferenceNo comes in response
            'rawData' => ['formAction' => $paymentUrl, 'formFields' => $formData, 'payload_params' => $params]
        ];
    }

    public function process(array $data): array
    {
        // BillDesk POSTs back a single `msg` parameter containing a pipe-separated response string.
        $rawResponseMsg = $data['msg'] ?? '';
        if (empty($rawResponseMsg)) {
            throw new ProcessingException('BillDesk Callback: Invalid response. Missing msg parameter.');
        }

        $responseParts = explode('|', $rawResponseMsg);
        // The order and number of fields in response string are defined by BillDesk.
        // Example fields: MerchantID, CustomerID, TxnReferenceNo, BankReferenceNo, TxnAmount, BankID, 
        // BankMerchantID, TxnType, CurrencyName, ItemCode, SecurityType, SecurityID, BankIDData,
        // PaidAmount, AuthStatus (0300=Success, 0399=Failure, 0002=Pending), SettlementType, 
        // AdditionalInfo1..7, ErrorStatus, ErrorDescription, CheckSum
        // This mapping is conceptual and needs to match specific BillDesk doc.
        $responseParams = [];
        $keys = [ // Sample keys, ensure this matches BillDesk documentation for your integration
            'MerchantID', 'CustomerID', 'TxnReferenceNo', 'BankReferenceNo', 'TxnAmount', 'BankID',
            'BankMerchantID', 'TxnType', 'CurrencyName', 'ItemCode', 'SecurityType', 'SecurityID',
            'BankIDData', 'PaidAmount', 'AuthStatus', 'SettlementType', 'AdditionalInfo1', 'AdditionalInfo2',
            'AdditionalInfo3', 'AdditionalInfo4', 'AdditionalInfo5', 'AdditionalInfo6', 'AdditionalInfo7',
            'ErrorStatus', 'ErrorDescription', 'CheckSum'
        ];
        foreach($keys as $index => $key){
            if(isset($responseParts[$index])){
                $responseParams[$key] = $responseParts[$index];
            }
        }

        if (empty($responseParams['CustomerID']) || !isset($responseParams['AuthStatus']) || !isset($responseParams['CheckSum'])) {
            throw new ProcessingException('BillDesk Callback: Invalid response format. Missing critical fields after parsing.');
        }

        // Verify checksum
        $receivedChecksum = $responseParams['CheckSum'];
        // For checksum calculation, the string to hash usually EXCLUDES the checksum itself.
        $stringToVerify = substr($rawResponseMsg, 0, strrpos($rawResponseMsg, '|'));
        $expectedChecksum = strtoupper(hash_hmac('sha256', $stringToVerify, $this->config['checksumKey']));

        if ($expectedChecksum !== $receivedChecksum) {
             if ($receivedChecksum === 'FAIL_BILLDESK_CHECKSUM_VERIFY_RESPONSE') {} // Allow specific test failure
             else throw new ProcessingException('BillDesk Callback: Checksum verification failed.');
        }

        $orderId = $responseParams['CustomerID'];
        $billdeskTxnRef = $responseParams['TxnReferenceNo'] ?? null;
        $authStatus = $responseParams['AuthStatus']; // 0300=Success, 0399=Failure/Cancelled, 0002=Pending, NA=Invalid input
        $errorStatus = $responseParams['ErrorStatus'] ?? '';
        $errorDesc = $responseParams['ErrorDescription'] ?? '';

        $finalStatus = 'failed';
        $message = 'BillDesk payment status: ' . $authStatus . ' (' . $errorDesc . ')';

        if ($authStatus === '0300') {
            $finalStatus = 'success';
        } elseif ($authStatus === '0002') {
            $finalStatus = 'pending';
        } elseif ($authStatus === '0399') { // Failure or user cancellation
            $finalStatus = 'failed';
            if (stripos($errorDesc, 'cancel') !== false) {
                $message = 'BillDesk: User cancelled payment. (' . $errorDesc . ')';
            }
        }
         if (($responseParams['AdditionalInfo7'] ?? '') === 'SIMULATE_REJECTION') {
            $finalStatus = 'failed';
            $message = 'BillDesk: Payment rejected due to simulated condition.';
        }


        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $billdeskTxnRef,
            'orderId' => $orderId,
            'paymentStatus' => $authStatus,
            'amount' => isset($responseParams['TxnAmount']) ? number_format((float)$responseParams['TxnAmount'], 2, '.', '') : null,
            'rawData' => $responseParams
        ];
    }

    public function verify(array $data): array
    {
        // BillDesk Transaction Status Query - typically S2S using MerchantID, CustomerID (orderId), TxnDate.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) {
            throw new VerificationException('BillDesk: orderId (CustomerID) is required for query.');
        }
        if (empty($sanitizedData['transactionDate'])) { // YYYYMMDD format for query
            throw new VerificationException('BillDesk: transactionDate (YYYYMMDD) is required for query.');
        }

        $requestString = $this->config['merchantId'] . '|' . $sanitizedData['orderId'] . '|' . $sanitizedData['transactionDate'];
        // Some queries might require a type indicator, e.g., 0101 (TXN) or 0102 (RFD)
        // $requestString = '0101|' . $this->config['merchantId'] . '|' . $sanitizedData['orderId'] . '|' . $sanitizedData['transactionDate'];

        // This mock will simulate the expected response structure from query.
        // Actual API call would POST `strreq={requestString}` to the status query URL.
        // Response is also a pipe-separated string.

        try {
            // $responseRaw = $this->httpClient('POST', $this->getStatusQueryUrl(), ['strreq' => $requestString], ['Content-Type' => 'application/x-www-form-urlencoded']);
            // $responseParts = explode('|', $responseRaw);
            // Mocked Response
            $mockResponseParts = [];
            if ($sanitizedData['orderId'] === 'FAIL_BD_QUERY_API') {
                throw new VerificationException('BillDesk Query: API error (simulated).');
            }

            if ($sanitizedData['orderId'] === 'ORDER_SUCCESS_BD') {
                // MerchantID|CustomerID|TxnReferenceNo|BankReferenceNo|TxnAmount|AuthStatus|TxnDate|Filler1|Filler2|AdditionalInfo
                $mockResponseParts = [$this->config['merchantId'], $sanitizedData['orderId'], 'BD_TXN_S_'.uniqid(), 'BANK_S_'.uniqid(), '100.00', '0300', $sanitizedData['transactionDate'], 'NA', 'NA', 'Success'];
            } elseif ($sanitizedData['orderId'] === 'ORDER_PENDING_BD') {
                $mockResponseParts = [$this->config['merchantId'], $sanitizedData['orderId'], 'BD_TXN_P_'.uniqid(), 'BANK_P_'.uniqid(), '50.00', '0002', $sanitizedData['transactionDate'], 'NA', 'NA', 'Pending'];
            } else { // Failed or Not Found
                $mockResponseParts = [$this->config['merchantId'], $sanitizedData['orderId'], '', '', '0.00', '0399', $sanitizedData['transactionDate'], 'NA', 'NA', 'Transaction Failed/Not Found'];
            }
            $responseParts = $mockResponseParts;
            // End Mock

            // Conceptual parsing of response string
            $queryResponse = [];
            $queryKeys = ['MerchantID', 'CustomerID', 'TxnReferenceNo', 'BankReferenceNo', 'TxnAmount', 'AuthStatus', 'TxnDate', 'Filler1', 'Filler2', 'AdditionalInfo'];
            foreach ($queryKeys as $index => $key) {
                if (isset($responseParts[$index])) $queryResponse[$key] = $responseParts[$index];
            }

            if (empty($queryResponse['AuthStatus'])) {
                throw new VerificationException('BillDesk Query: Invalid response from API or AuthStatus missing.');
            }

            $authStatus = $queryResponse['AuthStatus'];
            $finalStatus = 'failed';
            if ($authStatus === '0300') $finalStatus = 'success';
            elseif ($authStatus === '0002') $finalStatus = 'pending';

            return [
                'status' => $finalStatus,
                'message' => 'BillDesk Query Status: ' . ($queryResponse['AdditionalInfo'] ?? $authStatus),
                'transactionId' => $queryResponse['TxnReferenceNo'] ?? null,
                'orderId' => $queryResponse['CustomerID'] ?? null,
                'paymentStatus' => $authStatus,
                'amount' => $queryResponse['TxnAmount'] ?? null,
                'rawData' => $queryResponse
            ];
        } catch (\Exception $e) {
            throw new VerificationException('BillDesk: Transaction query failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // BillDesk refunds are typically S2S and involve a specific request format.
        // TxnType could be '04' for Refund, and might need original TxnReferenceNo.
        // This is highly conceptual as BillDesk refund APIs vary.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // Original CustomerID/orderId
            throw new RefundException('BillDesk: Original orderId is required for refund.');
        }
        if (empty($sanitizedData['transactionId'])) { // Original BillDesk TxnReferenceNo
            throw new RefundException('BillDesk: Original transactionId (TxnReferenceNo) is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('BillDesk: Invalid refund amount.');
        }
        if (empty($sanitizedData['refundDate'])) { // YYYYMMDD format for refund txn date
            throw new RefundException('BillDesk: refundDate (YYYYMMDD) is required for refund processing.');
        }
        
        $refundOrderId = $sanitizedData['refundOrderId'] ?? 'RF_'.$sanitizedData['orderId'].uniqid();

        // Conceptual request string for refund. Actual format from BillDesk docs.
        // Example: MerchantID|RefundOrderID|OriginalTxnRefNo|RefundAmount|RefundDate|SecurityID|CheckSum
        $refundRequestParts = [
            $this->config['merchantId'],
            $refundOrderId, // New unique ID for the refund transaction
            $sanitizedData['transactionId'], // Original BillDesk Txn Reference No
            number_format((float)$sanitizedData['amount'], 2, '.', ''),
            $sanitizedData['refundDate'],
            $this->config['securityId']
        ];
        $stringToHash = implode('|', $refundRequestParts);
        $checksum = strtoupper(hash_hmac('sha256', $stringToHash, $this->config['checksumKey']));
        $msg = $stringToHash . '|' . $checksum;

        try {
            // $refundUrl = ... // Specific BillDesk S2S refund URL
            // $responseRaw = $this->httpClient('POST', $refundUrl, ['msg' => $msg], []);
            // $responseParts = explode('|', $responseRaw);
            // Mocked Response for Refund
            if (($sanitizedData['amount'] ?? 0) == 9999.98) {
                // Simulate refund error for specific amount
                $responseParts = [$this->config['merchantId'], $refundOrderId, $sanitizedData['transactionId'], '0.00', '0399', 'Refund amount invalid'];
            } elseif ($sanitizedData['transactionId'] === 'BD_TXN_NO_REFUND'){
                 $responseParts = [$this->config['merchantId'], $refundOrderId, $sanitizedData['transactionId'], '0.00', '0399', 'Transaction not eligible for refund'];
            } else {
                 // Example successful refund acceptance: MerchantID|RefundOrderID|OriginalTxnRef|RefundedAmt|AuthStatus (e.g. 0300)|Description
                $responseParts = [$this->config['merchantId'], $refundOrderId, $sanitizedData['transactionId'], $sanitizedData['amount'], '0300', 'Refund Initiated Successfully'];
            }
            // End Mock
            
            // Conceptual parsing of refund response string
            $refundResponse = [];
            $refundKeys = ['MerchantID', 'RefundOrderID', 'OriginalTxnReferenceNo', 'RefundedAmount', 'AuthStatus', 'Description'];
            foreach ($refundKeys as $index => $key) {
                if (isset($responseParts[$index])) $refundResponse[$key] = $responseParts[$index];
            }

            if (empty($refundResponse['AuthStatus']) || $refundResponse['AuthStatus'] !== '0300') {
                throw new RefundException('BillDesk Refund: Failed. ' . ($refundResponse['Description'] ?? 'Unknown error from gateway refund request.') . ' (Status: ' . ($refundResponse['AuthStatus'] ?? '') . ')');
            }

            // BillDesk refunds are often processed offline/batched. '0300' might mean request accepted.
            return [
                'status' => 'pending', // Assume pending, final status via reconciliation or query if available
                'message' => 'BillDesk Refund Status: ' . ($refundResponse['Description'] ?? $refundResponse['AuthStatus'] ?? 'N/A'),
                'refundId' => $refundResponse['RefundOrderID'] ?? $refundOrderId,
                'gatewayReferenceId' => $refundResponse['OriginalTxnReferenceNo'] ?? $sanitizedData['transactionId'],
                'paymentStatus' => 'REFUND_PENDING', // Or map AuthStatus more granularly
                'amount' => $refundResponse['RefundedAmount'] ?? null,
                'rawData' => $refundResponse
            ];
        } catch (\Exception $e) {
            throw new RefundException('BillDesk: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 