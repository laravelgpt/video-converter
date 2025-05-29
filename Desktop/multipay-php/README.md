# Multipay PHP - Multi-Gateway Payment Processing Library

[![Latest Stable Version](https://poser.pugx.org/multipay/multipay-php/v/stable)](https://packagist.org/packages/multipay/multipay-php) 
[![Total Downloads](https://poser.pugx.org/multipay/multipay-php/downloads)](https://packagist.org/packages/multipay/multipay-php) 
[![License](https://poser.pugx.org/multipay/multipay-php/license)](https://packagist.org/packages/multipay/multipay-php)

Multipay PHP provides a consistent and fluent API for interacting with various payment gateways. This library aims to simplify the integration of payment processing into your PHP applications, including Laravel projects.

**Note:** This library currently provides mocked implementations for the gateways. Real API interactions, especially secure HTTP calls and precise signature generation, need to be fully implemented for production use. We highly recommend using a robust HTTP client like Guzzle.

## Supported Gateways (Mocked)

*   BinancePay
*   bKash
*   Nagad
*   Upay
*   STC Pay
*   Urpay
*   Barq
*   PayPal (REST API v2)
*   PhonePe
*   Paytm
*   Razorpay
*   MobiKwik
*   MobilyPay (Saudi Arabia)
*   Easypaisa (Pakistan)
*   Jazzcash (Pakistan)
*   Omantel (Oman)
*   BankDhofar (Oman)
*   American Express
*   GooglePay (Conceptual)
*   Stripe (PaymentIntents)
*   Adyen
*   TwoCheckout (Verifone)
*   Wise (formerly TransferWise)
*   Braintree
*   AmazonPay
*   Mpesa (Kenya)
*   Flutterwave (Nigeria)
*   Paystack (Nigeria)
*   PayFast (South Africa)
*   PeachPayments (South Africa, Kenya, Mauritius)
*   DpoPay (Africa)
*   Interswitch (Nigeria, Africa)
*   Alipay
*   WeChatPay
*   UnionPay
*   BillDesk (India)
*   AmarPay (Bangladesh)
*   SSLCommerz (Bangladesh)
*   PortWallet (Bangladesh)

## Requirements

*   PHP >= 8.0
*   JSON Extension
*   OpenSSL Extension

## Installation

You can install the package via Composer:

```bash
composer require multipay/multipay-php
```

It is highly recommended to also install a PSR-18 HTTP client like Guzzle for production environments if you plan to implement the actual HTTP calls:

```bash
composer require guzzlehttp/guzzle
```

## Basic Usage

```php
use Multipay\Payment\PaymentProcessor;
use Multipay\Payment\Gateways\BinancePayGateway; // Or any other gateway
use Multipay\Payment\Gateways\BkashGateway;

// 1. Initialize the Payment Processor
$processor = new PaymentProcessor();

// 2. Configure and Add Gateways
$binanceConfig = [
    'apiKey' => 'your_binance_api_key',
    'secretKey' => 'your_binance_secret_key',
    'isSandbox' => true,
];
$processor->addGateway('binance', BinancePayGateway::class, $binanceConfig);

$bkashConfig = [
    'appKey' => 'your_bkash_app_key',
    'appSecret' => 'your_bkash_app_secret',
    'username' => 'your_bkash_username',
    'password' => 'your_bkash_password',
    'isSandbox' => true,
    'callbackUrl' => 'https://your-domain.com/bkash/callback'
];
$processor->addGateway('bkash', BkashGateway::class, $bkashConfig);

// 3. Perform Operations

// Initialize a payment (e.g., create an order, get a payment URL)
try {
    $initData = [
        'amount' => 100.50,
        'orderId' => 'ORDER_12345',
        'currency' => 'USDT', // For Binance
        // 'callbackUrl' => 'https://your-domain.com/payment/callback/binance' // Optional, can be in config
    ];
    $response = $processor->initialize('binance', $initData);

    if ($response['status'] === 'pending_user_action' && !empty($response['paymentUrl'])) {
        // Redirect user to $response['paymentUrl']
        header('Location: ' . $response['paymentUrl']);
        exit;
    } elseif ($response['status'] === 'success') {
        // Payment initialized directly, or further steps required based on gateway
        var_dump($response);
    } else {
        // Handle other statuses or errors
        echo "Initialization failed: " . $response['message'];
    }

} catch (\Multipay\Payment\Exceptions\PaymentException $e) {
    // Handle specific payment exceptions
    echo "Payment Error: " . $e->getMessage();
} catch (\Exception $e) {
    // Handle other general exceptions
    echo "General Error: " . $e->getMessage();
}


// Process a payment (e.g., handle a callback, capture a payment)
// This often happens in a separate callback script based on the gateway's flow.
// For example, after PayPal redirects back to your `returnUrl`:
// $paypalCallbackData = ['token' => $_GET['token'], 'PayerID' => $_GET['PayerID']];
// $processResponse = $processor->process('paypal', $paypalCallbackData);

// Verify a payment
try {
    $verifyData = ['gatewayReferenceId' => 'PAYPAL_ORDER_ID_OR_BKASH_PAYMENT_ID']; // Use the ID from initialize() or process()
    $verification = $processor->verify('paypal', $verifyData);
    var_dump($verification);
} catch (\Exception $e) {
    echo "Verification Error: " . $e->getMessage();
}

// Refund a payment
try {
    $refundData = [
        'transactionId' => 'CAPTURE_ID_OR_TRX_ID', // The actual transaction ID from a successful payment
        'amount' => 50.00,
        // 'currency' => 'USD', // For PayPal, original currency is important
        // 'reason' => 'Customer request'
    ];
    $refundResponse = $processor->refund('paypal', $refundData);
    var_dump($refundResponse);
} catch (\Exception $e) {
    echo "Refund Error: " . $e->getMessage();
}

```

## Laravel Integration (Conceptual)

While this package doesn't include a Laravel Service Provider out-of-the-box yet, you can easily integrate it. Future versions may include one.

1.  **Configuration**: Publish a config file (`config/multipay.php`) where you can define your gateway credentials and settings.
2.  **Service Provider**: Create a `MultipayServiceProvider` that registers the `PaymentProcessor` in the service container, configured with the settings from your `config/multipay.php` file.
3.  **Facade** (Optional): Create a `Multipay` facade for easy access to the `PaymentProcessor` instance.

**Example `MultipayServiceProvider` (simplified):**

```php
namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Multipay\Payment\PaymentProcessor;
// ... import your gateway classes ...

class MultipayServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton(PaymentProcessor::class, function ($app) {
            $processor = new PaymentProcessor();
            $config = $app['config']['multipay']; // Assuming you have config/multipay.php

            foreach ($config['gateways'] as $name => $gatewayConfig) {
                if (isset($gatewayConfig['class']) && class_exists($gatewayConfig['class'])) {
                    $processor->addGateway($name, $gatewayConfig['class'], $gatewayConfig['config'] ?? []);
                }
            }
            return $processor;
        });
    }

    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/multipay.php' => config_path('multipay.php'),
        ], 'config');
    }
}
```

**Example `config/multipay.php`:**

```php
<?php

return [
    'gateways' => [
        'paypal' => [
            'class' => Multipay\Payment\Gateways\PayPalGateway::class,
            'config' => [
                'clientId' => env('PAYPAL_CLIENT_ID'),
                'clientSecret' => env('PAYPAL_CLIENT_SECRET'),
                'isSandbox' => env('PAYPAL_SANDBOX', true),
                'returnUrl' => env('PAYPAL_RETURN_URL', 'https://example.com/paypal/success'),
                'cancelUrl' => env('PAYPAL_CANCEL_URL', 'https://example.com/paypal/cancel'),
            ]
        ],
        'binance' => [
            'class' => Multipay\Payment\Gateways\BinancePayGateway::class,
            'config' => [
                'apiKey' => env('BINANCE_API_KEY'),
                'secretKey' => env('BINANCE_SECRET_KEY'),
                'isSandbox' => env('BINANCE_SANDBOX', true),
            ]
        ],
        // ... other gateways
    ]
];
```

## Testing

Run the unit tests using PHPUnit:

```bash
composer test
```

Or to generate a coverage report:

```bash
composer test-coverage
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for bugs, features, or improvements.

When contributing, please ensure:

*   Code follows PSR-12 coding standards.
*   New functionality includes unit tests.
*   Documentation is updated where necessary.

## Security

**IMPORTANT**: This library provides a structural framework and mocked implementations. For production use:

*   **Thoroughly review and implement the actual API communication logic** for each gateway, including secure handling of HTTP requests (use a robust client like Guzzle), responses, and error conditions.
*   **Implement correct and secure signature generation and verification** as per each gateway's official documentation. This is critical for authenticating requests and callbacks.
*   **Handle sensitive data (API keys, secrets) securely.** Do not hardcode them. Use environment variables or a secure configuration management system.
*   **Validate all incoming data**, especially from callbacks, to prevent injection or manipulation attacks.
*   Consider security headers and other best practices for web application security.

If you discover any security vulnerabilities, please email [your-security-email@example.com](mailto:your-security-email@example.com) instead of using the issue tracker.

## License

The Multipay PHP library is open-sourced software licensed under the [MIT license](LICENSE).
