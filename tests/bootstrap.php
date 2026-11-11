<?php

declare(strict_types=1);

/**
 * Test bootstrap.
 *
 * `phpunit.xml` used to name `vendor/autoload.php`, which a plugin checkout
 * does not have unless `composer install` was run against the kernel as a
 * path dependency — so the suite could not start from a bare clone. This
 * resolves the kernel the way the sibling plugins do, most specific first:
 *
 *   1. HKM_KERNEL_PATH     — an explicit kernel checkout
 *   2. vendor/autoload.php — composer-installed (CI)
 *   3. ../../../PHP        — the conventional workspace layout
 *
 * A composer-installed run is unchanged: it takes branch 2 and never reaches
 * the workspace probe.
 */

$pluginRoot = \dirname(__DIR__);

spl_autoload_register(static function (string $class) use ($pluginRoot): void {
    // The longer prefix first, so the fixtures are not looked up as source.
    $map = [
        'Tests\\Unit\\Plugins\\WebSocket\\' => $pluginRoot . '/tests/',
        'Plugins\\WebSocket\\'              => $pluginRoot . '/',
    ];

    foreach ($map as $prefix => $base) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }

        $path = $base . str_replace('\\', '/', substr($class, \strlen($prefix))) . '.php';

        if (is_file($path)) {
            require_once $path;
        }

        return;
    }
});

if (is_file($pluginRoot . '/vendor/autoload.php')) {
    require_once $pluginRoot . '/vendor/autoload.php';

    return;
}

$kernelRoot = getenv('HKM_KERNEL_PATH') ?: \dirname($pluginRoot, 3) . '/PHP';

if (!is_file($kernelRoot . '/vendor/autoload.php')) {
    fwrite(STDERR, \sprintf(
        "\nCannot find the kernel. Looked in %s.\nSet HKM_KERNEL_PATH to a checkout with vendor/ installed,"
        . " or run `composer install`.\n\n",
        $kernelRoot,
    ));
    exit(1);
}

require_once $kernelRoot . '/vendor/autoload.php';
