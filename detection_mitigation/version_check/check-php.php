<?php
// check-php.php  -  shows your exact PHP version once, then deletes itself.
// Upload to your site's main folder, open https://yourdomain.com/check-php.php once, done.
// Free online checker: https://simgen.dev/php-patch-check
echo 'PHP ' . PHP_VERSION;
echo PHP_VERSION_ID < 80200
  ? '  ->  END OF LIFE, no official update. Upgrade needed.'
  : '  ->  supported. Apply the latest patch for your branch.';
// Remove this file so your version is not left public.
echo @unlink(__FILE__) ? '  (this file has deleted itself)' : '  (please delete this file now)';
