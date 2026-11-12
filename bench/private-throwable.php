<?php

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Request;

function vn_private_write_diagnostic(string $file, array $metadata): bool
{
    $previous = umask(0077);
    try {
        $output = @fopen($file, 'x');
    } finally {
        umask($previous);
    }
    if ($output === false) {
        return false;
    }
    try {
        $payload = json_encode($metadata, JSON_THROW_ON_ERROR);
        return @fwrite($output, $payload) === strlen($payload);
    } finally {
        fclose($output);
    }
}

function vn_private_observe_throwable($app, array $manifest, string $correlation, string $receipt, string $armed, string $ready): void
{
    $matchesNonce = static function ($nonce) use ($correlation): bool {
        return is_string($nonce) && preg_match('/\A[a-f0-9]{64}\z/', $nonce) === 1 &&
            hash_equals($correlation, hash('sha256', $nonce));
    };
    try {
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        $path = $_SERVER['REQUEST_URI'] ?? '';
        if (!$matchesNonce($_SERVER['HTTP_X_VIBENEST_FIXTURE_DIAGNOSTIC'] ?? '')) {
            return;
        }
        if ($method === 'GET' && $path === '/api/health') {
            $revalidate = ini_get('opcache.revalidate_freq');
            $fileCache = ini_get('opcache.file_cache');
            $preload = ini_get('opcache.preload');
            vn_private_write_diagnostic($ready, [
                'correlation' => $correlation, 'fpm' => PHP_SAPI === 'fpm-fcgi',
                'opcacheEnabled' => filter_var(ini_get('opcache.enable'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE),
                'timestampValidation' => filter_var(ini_get('opcache.validate_timestamps'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE),
                'revalidateSeconds' => is_string($revalidate) && preg_match('/\A[0-9]{1,5}\z/', $revalidate) === 1 ? (int) $revalidate : null,
                'fileCacheDisabled' => $fileCache === false || $fileCache === '',
                'fileCacheDirectiveAvailable' => $fileCache !== false,
                'preloadDisabled' => $preload === false || $preload === '',
                'preloadDirectiveAvailable' => $preload !== false,
                'workerReuseConfigured' => getenv('PHP_FPM_PM_CONTROL') === 'ondemand' && getenv('PHP_FPM_PM_MAX_REQUESTS') === '0',
            ]);
            return;
        }
        if ($method !== 'POST' || $path !== '/api/v1/applications/public' ||
            !vn_private_write_diagnostic($armed, ['correlation' => $correlation])) {
            return;
        }
    } catch (Throwable) {
        return;
    }

    $observe = static function (Throwable $error, Request $request) use ($manifest, $matchesNonce, $correlation, $receipt): void {
        try {
            if (!$request->isMethod('POST') || $request->getPathInfo() !== '/api/v1/applications/public' ||
                !$matchesNonce($request->headers->get('X-VibeNest-Fixture-Diagnostic', ''))) {
                return;
            }
            $class = $error::class;
            $file = $error->getFile();
            $line = $error->getLine();
            $code = $error->getCode();
            $relativeFile = str_starts_with($file, '/var/www/html/') ? substr($file, strlen('/var/www/html/')) : '';
            $classKnown = in_array($class, $manifest['classes'], true);
            $fileKnown = in_array($relativeFile, $manifest['files'], true) && $line > 0 && $line <= 99999;
            $codeKnown = (is_int($code) || is_string($code)) && in_array((string) $code, $manifest['codes'], true);
            $metadata = ['correlation' => $correlation, 'observation' => 'observed',
                'classStatus' => $classKnown ? 'allowlisted' : 'unknown',
                'fileStatus' => $fileKnown ? 'allowlisted' : 'unknown',
                'codeStatus' => $codeKnown ? 'allowlisted' : 'unknown'];
            if ($classKnown) {
                $metadata['exceptionClass'] = $class;
            }
            if ($fileKnown) {
                $metadata['providerFile'] = $relativeFile;
                $metadata['providerLine'] = $line;
            }
            if ($codeKnown) {
                $metadata['exceptionCode'] = $code;
            }

            vn_private_write_diagnostic($receipt, $metadata);
        } catch (Throwable) {
            // Evidence collection must not change provider exception handling.
        }
    };

    $app->afterResolving(ExceptionHandler::class, static function ($handler) use ($app, $observe): void {
        if (!$handler instanceof Handler) {
            return;
        }
        $handler->reportable(static function (Throwable $error) use ($app, $observe): void {
            try {
                if ($app->bound('request') && ($request = $app->make('request')) instanceof Request) {
                    $observe($error, $request);
                }
            } catch (Throwable) {
                // The original exception must still be reported.
            }
        });
        $handler->renderable(static function (Throwable $error, Request $request) use ($observe) {
            $observe($error, $request);
            return null;
        });
    });
}
