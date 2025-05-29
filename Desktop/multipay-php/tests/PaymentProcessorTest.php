<?php

namespace Multipay\Tests;

use Multipay\Payment\PaymentProcessor;
use Multipay\Payment\Gateways\BinancePayGateway;
use Multipay\Payment\Gateways\BkashGateway;
use Multipay\Payment\Exceptions\GatewayNotFoundException;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use PHPUnit\Framework\TestCase;

class PaymentProcessorTest extends TestCase
{
    private PaymentProcessor $processor;
    private array $binanceConfig = [
        'apiKey' => 'test_api_key',
        'secretKey' => 'test_secret_key',
        'isSandbox' => true,
    ];

    private array $bkashConfig = [
        'appKey' => 'bkash_app_key',
        'appSecret' => 'bkash_app_secret',
        'username' => 'bkash_username',
        'password' => 'bkash_password',
        'isSandbox' => true,
        'callbackUrl' => 'https://example.com/bkash/callback'
    ];

    protected function setUp(): void
    {
        $this->processor = new PaymentProcessor();
        $this->processor->addGateway(
            'binance',
            BinancePayGateway::class,
            $this->binanceConfig
        );
        $this->processor->addGateway(
            'bkash',
            BkashGateway::class,
            $this->bkashConfig
        );
    }

    public function testAddAndGetGateway(): void
    {
        $gateway = $this->processor->getGateway('binance');
        $this->assertInstanceOf(BinancePayGateway::class, $gateway);

        $gatewayBkash = $this->processor->getGateway('bkash');
        $this->assertInstanceOf(BkashGateway::class, $gatewayBkash);
    }

    public function testGetInvalidGatewayThrowsException(): void
    {
        $this->expectException(GatewayNotFoundException::class);
        $this->processor->getGateway('non_existent_gateway');
    }

    public function testAddInvalidGatewayClassThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->processor->addGateway('invalid', \stdClass::class, []);
    }

    public function testGatewayInstantiationWithInvalidConfigBinance(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('BinancePay: API Key is required.');
        $this->processor->addGateway('binance_invalid_config', BinancePayGateway::class, ['secretKey' => 'onlysecret']);
        $this->processor->getGateway('binance_invalid_config');
    }

    public function testGatewayInstantiationWithInvalidConfigBkash(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('bKash: appKey is required.');
        $this->processor->addGateway('bkash_invalid_config', BkashGateway::class, ['appSecret' => 'secret']);
        $this->processor->getGateway('bkash_invalid_config');
    }

    // --- BinancePay Tests ---
    public function testInitializePaymentBinance(): void
    {
        $result = $this->processor->initialize('binance', ['amount' => 100, 'orderId' => 'order123', 'currency' => 'USDT']);
        $this->assertEquals('pending_user_action', $result['status']);
        $this->assertArrayHasKey('gatewayReferenceId', $result);
        $this->assertArrayHasKey('paymentUrl', $result);
    }

    public function testInitializePaymentBinanceWithMissingParamsThrowsException(): void
    {
        $this->expectException(InitializationException::class);
        $this->expectExceptionMessage('BinancePay: Invalid or missing amount for initialization.');
        $this->processor->initialize('binance', ['orderId' => 'order123']);
    }
    
    public function testInitializePaymentBinanceWithSimulatedApiError(): void
    {
        $this->expectException(InitializationException::class);
        $this->expectExceptionMessage('BinancePay: API rejected initialization (simulated).');
        $this->processor->initialize('binance', ['amount' => 999, 'orderId' => 'order_error', 'currency' => 'USDT']);
    }

    public function testProcessPaymentBinance(): void
    {
        $result = $this->processor->process('binance', ['transactionId' => 'txn_abc123']);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals('txn_abc123', $result['transactionId']);
    }

    public function testVerifyPaymentBinance(): void
    {
        $result = $this->processor->verify('binance', ['gatewayReferenceId' => 'order123']);
        $this->assertEquals('success', $result['status']); 
        $this->assertArrayHasKey('transactionId', $result);
        $this->assertEquals('PAID', $result['paymentStatus']);
    }
    
    public function testVerifyPaymentBinancePending(): void
    {
        $result = $this->processor->verify('binance', ['gatewayReferenceId' => 'fail_verify']); // fail_verify is not specific to Binance model, but test mock logic
        $this->assertEquals('pending', $result['status']);
        $this->assertEquals('PENDING', $result['paymentStatus']);
    }

    public function testRefundPaymentBinance(): void
    {
        $result = $this->processor->refund('binance', ['transactionId' => 'txn_abc123', 'amount' => 50]);
        $this->assertEquals('success', $result['status']);
        $this->assertArrayHasKey('refundId', $result);
    }

    // --- Bkash Tests ---
    public function testInitializePaymentBkash(): void
    {
        $initData = [
            'amount' => 150.75,
            'orderId' => 'BKORDER_001',
            'payerReference' => '01234567890',
            'callbackUrl' => 'https://my-shop.com/bkash/confirm'
        ];
        $result = $this->processor->initialize('bkash', $initData);
        $this->assertEquals('pending_user_action', $result['status']);
        $this->assertArrayHasKey('gatewayReferenceId', $result); // paymentID
        $this->assertArrayHasKey('paymentUrl', $result);       // bkashURL
        $this->assertStringContainsString('mock_bkash_trx_', $result['gatewayReferenceId']);
    }

    public function testInitializePaymentBkashTokenError(): void
    {
        $this->expectException(InitializationException::class);
        $this->expectExceptionMessage('bKash: Failed to acquire auth token (simulated error).');
        $customBkashConfig = array_merge($this->bkashConfig, ['appKey' => 'force_token_error']);
        $this->processor->addGateway('bkash_token_error', BkashGateway::class, $customBkashConfig);
        $this->processor->initialize('bkash_token_error', ['amount' => 100, 'orderId' => 'BK002']);
    }

    public function testProcessPaymentBkashActuallyVerifies(): void
    {
        // Bkash process() internally calls verify()
        $result = $this->processor->process('bkash', ['paymentID' => 'some_payment_id']);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals('Completed', $result['paymentStatus']);
        $this->assertNotNull($result['transactionId']);
    }

    public function testVerifyPaymentBkashFailed(): void
    {
        $result = $this->processor->verify('bkash', ['paymentID' => 'fail_verify']);
        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('Failed', $result['paymentStatus']);
        $this->assertNull($result['transactionId']);
    }

    public function testRefundPaymentBkash(): void
    {
        $refundData = [
            'paymentID' => 'PAYID_XYZ123',
            'transactionId' => 'TRXBKASH789',
            'amount' => 75.00,
            'reason' => 'Item out of stock'
        ];
        $result = $this->processor->refund('bkash', $refundData);
        $this->assertEquals('success', $result['status']);
        $this->assertArrayHasKey('refundId', $result);
        $this->assertStringContainsString('REF', $result['refundId']);
    }
} 